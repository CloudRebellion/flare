// oidc-prelink is a standalone operator; it never imports server startup,
// migrations, analytics, telemetry, or HTTP handlers.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"os"

	"github.com/bright-interaction/flare/internal/oidcprelink"
)

func run(args []string, getenv func(string) string, out io.Writer) int {
	flags := flag.NewFlagSet("oidc-prelink", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	request := flags.String("request", "", "private request JSON file")
	apply := flags.Bool("apply", false, "apply one exact reviewed binding")
	expected := flags.String("expected-authority-sha256", "", "authority hash returned by read-only plan")
	expectedRequest := flags.String("expected-request-sha256", "", "canonical request hash returned by read-only plan")
	fail := func(code string) int {
		_ = json.NewEncoder(out).Encode(map[string]string{"status": "refused", "error": code})
		return 1
	}
	if flags.Parse(args) != nil || flags.NArg() != 0 || *request == "" {
		return fail("ARGUMENTS_REFUSED")
	}
	r, err := oidcprelink.ReadFile(*request)
	if err != nil {
		return fail(err.Error())
	}
	result, err := oidcprelink.Execute(context.Background(), getenv("DATABASE_URL"), r, *apply, *expected, *expectedRequest)
	if err != nil {
		if c, ok := err.(oidcprelink.Code); ok {
			return fail(string(c))
		}
		return fail("INTERNAL_REFUSED")
	}
	if json.NewEncoder(out).Encode(result) != nil {
		return 1
	}
	return 0
}
func main() { os.Exit(run(os.Args[1:], os.Getenv, os.Stdout)) }
