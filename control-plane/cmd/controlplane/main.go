package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Deep-0610/agentguard/control-plane/internal/api"
	"github.com/Deep-0610/agentguard/control-plane/internal/config"
	"github.com/Deep-0610/agentguard/control-plane/internal/store"
)

func main() {
	if len(os.Args)>1 && os.Args[1]=="bootstrap" { if err:=bootstrap(os.Args[2:]); err!=nil { log.Fatal(err) }; return }
	if len(os.Args)>1 && os.Args[1]=="migrate" { if err:=migrate(); err!=nil { log.Fatal(err) }; return }
	if err:=serve(); err!=nil { log.Fatal(err) }
}
func openStore(ctx context.Context)(config.Config,*store.Store,error) {
	c,err:=config.Load(); if err!=nil{return c,nil,err}
	s,err:=store.Open(ctx,c.DatabaseURL,c.APIKeyPepper); return c,s,err
}
func bootstrap(args []string) error {
	fs:=flag.NewFlagSet("bootstrap",flag.ContinueOnError); name:=fs.String("organization","","initial organization name")
	if err:=fs.Parse(args);err!=nil{return err}; if *name==""{return fmt.Errorf("usage: controlplane bootstrap --organization NAME")}
	ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
	_,s,err:=openStore(ctx);if err!=nil{return err};defer s.Close()
	if err=s.Migrate(ctx);err!=nil{return err}
	tenant,token,err:=s.Bootstrap(ctx,*name);if err!=nil{return err}
	fmt.Printf("Organization ID: %s\nInitial owner API key (shown once):\n%s\nStore this key in a secret manager. It cannot be retrieved again.\n",tenant,token)
	return nil
}
func migrate() error {
	ctx,cancel:=context.WithTimeout(context.Background(),30*time.Second);defer cancel()
	_,s,err:=openStore(ctx);if err!=nil{return err};defer s.Close();return s.Migrate(ctx)
}
func serve() error {
	ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second);c,s,err:=openStore(ctx);cancel();if err!=nil{return err};defer s.Close()
	logger:=log.New(os.Stdout,"agentguard-control-plane ",log.LstdFlags|log.LUTC)
	server:=&http.Server{Addr:c.Address,Handler:api.New(s,logger).Handler(),ReadHeaderTimeout:5*time.Second,ReadTimeout:c.ReadTimeout,WriteTimeout:c.WriteTimeout,IdleTimeout:c.IdleTimeout,MaxHeaderBytes:1<<20}
	errCh:=make(chan error,1);go func(){logger.Printf("listening addr=%s",c.Address);errCh<-server.ListenAndServe()}()
	stop:=make(chan os.Signal,1);signal.Notify(stop,syscall.SIGINT,syscall.SIGTERM)
	select { case err:=<-errCh: if err==http.ErrServerClosed{return nil};return err; case <-stop: }
	shutdownCtx,cancel:=context.WithTimeout(context.Background(),c.ShutdownTimeout);defer cancel();return server.Shutdown(shutdownCtx)
}
