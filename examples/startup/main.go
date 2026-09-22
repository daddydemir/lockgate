package main

import (
	"context"
	lockgate "lockgate/pkg/client"
	"log"
	"os"
	"time"
)

func main() {
	client := lockgate.New(lockgate.Config{URL: os.Getenv("LOCKGATE_URL"), Token: os.Getenv("LOCKGATE_TOKEN")})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	log.Print("Waiting for LockGate approval…")
	values, err := client.GetConfig(ctx)
	if err != nil {
		log.Fatal(err)
	}
	// Pass values directly to your database/library configuration. Do not log them.
	_ = values["DB_PASSWORD"]
	log.Print("Secrets received; application can start.")
}
