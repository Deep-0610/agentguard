FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/controlplane ./cmd/controlplane
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/controlplane /controlplane
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 CMD ["/controlplane", "healthcheck"]
ENTRYPOINT ["/controlplane"]
CMD ["serve"]
