FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/controlplane ./cmd/controlplane
FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /
COPY --from=build /out/controlplane /controlplane
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/controlplane"]
CMD ["serve"]
