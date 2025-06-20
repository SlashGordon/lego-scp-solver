package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

type MyUser struct {
	Email        string
	Registration *registration.Resource
	key          crypto.PrivateKey
}

func (u *MyUser) GetEmail() string {
	return u.Email
}

func (u *MyUser) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *MyUser) GetPrivateKey() crypto.PrivateKey {
	return u.key
}

// Version will be set by the build process
var version = "dev"

var rootCmd = &cobra.Command{
	Use:     "lego-scp-solver",
	Short:   "ACME certificate solver using SCP webroot method",
	Run:     runCertificate,
	Version: version,
}

func init() {
	rootCmd.Flags().StringP("email", "e", "", "Email address for ACME registration")
	rootCmd.Flags().StringP("domains", "d", "", "Comma-separated list of domains")
	rootCmd.Flags().StringP("account-key", "k", "account.key", "Path to ACME account private key")
	rootCmd.Flags().String("scp-host", "", "SCP server hostname")
	rootCmd.Flags().String("scp-user", "", "SCP username")
	rootCmd.Flags().String("scp-key", "", "Path to SSH private key for SCP")
	rootCmd.Flags().String("scp-webroot", "", "Remote webroot path for challenge files")
	rootCmd.Flags().String("cert-path", ".", "Directory to save certificates")
	
	// Bind flags to viper
	bindFlags()
	
	// Bind environment variables
	bindEnvVars()
}

func bindFlags() {
	// Ignore errors since these operations rarely fail
	_ = viper.BindPFlag("email", rootCmd.Flags().Lookup("email"))
	_ = viper.BindPFlag("domains", rootCmd.Flags().Lookup("domains"))
	_ = viper.BindPFlag("account.key", rootCmd.Flags().Lookup("account-key"))
	_ = viper.BindPFlag("scp.host", rootCmd.Flags().Lookup("scp-host"))
	_ = viper.BindPFlag("scp.user", rootCmd.Flags().Lookup("scp-user"))
	_ = viper.BindPFlag("scp.keypath", rootCmd.Flags().Lookup("scp-key"))
	_ = viper.BindPFlag("scp.webroot", rootCmd.Flags().Lookup("scp-webroot"))
	_ = viper.BindPFlag("cert.path", rootCmd.Flags().Lookup("cert-path"))
}

func bindEnvVars() {
	// Ignore errors since these operations rarely fail
	_ = viper.BindEnv("email", "LEGO_SCP_EMAIL")
	_ = viper.BindEnv("domains", "LEGO_SCP_DOMAINS")
	_ = viper.BindEnv("account.key", "LEGO_SCP_ACCOUNT_KEY")
	_ = viper.BindEnv("scp.host", "LEGO_SCP_HOST")
	_ = viper.BindEnv("scp.user", "LEGO_SCP_USER")
	_ = viper.BindEnv("scp.keypath", "LEGO_SCP_KEY_PATH")
	_ = viper.BindEnv("scp.webroot", "LEGO_SCP_WEBROOT_PATH")
	_ = viper.BindEnv("cert.path", "LEGO_SCP_CERT_PATH")
}

func runCertificate(cmd *cobra.Command, args []string) {
	email := viper.GetString("email")
	domains := viper.GetString("domains")

	if email == "" || domains == "" {
		log.Fatal("Email and domains are required")
	}

	domainList := strings.Split(domains, ",")
	for i, domain := range domainList {
		domainList[i] = strings.TrimSpace(domain)
	}

	privateKey, err := loadOrCreateAccountKey(viper.GetString("account.key"))
	if err != nil {
		log.Fatal(err)
	}

	myUser := MyUser{
		Email: email,
		key:   privateKey,
	}

	config := lego.NewConfig(&myUser)
	config.Certificate.KeyType = certcrypto.RSA2048

	client, err := lego.NewClient(config)
	if err != nil {
		log.Fatal(err)
	}

	scpSolver := NewSCPSolver(
		viper.GetString("scp.host"),
		viper.GetString("scp.user"),
		viper.GetString("scp.keypath"),
		viper.GetString("scp.webroot"),
	)

	err = client.Challenge.SetHTTP01Provider(scpSolver)
	if err != nil {
		log.Fatal(err)
	}

	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		log.Fatal(err)
	}
	myUser.Registration = reg

	request := certificate.ObtainRequest{
		Domains: domainList,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		log.Fatal(err)
	}

	// Save certificates to disk
	certPath := viper.GetString("cert.path")
	if err := os.MkdirAll(certPath, 0755); err != nil {
		log.Fatalf("Failed to create certificate directory: %v", err)
	}

	domain := domainList[0] // Use first domain as filename base
	
	// Save certificate
	certFile := filepath.Join(certPath, domain+".crt")
	if err := os.WriteFile(certFile, certificates.Certificate, 0644); err != nil {
		log.Fatalf("Failed to save certificate: %v", err)
	}

	// Save private key
	keyFile := filepath.Join(certPath, domain+".key")
	if err := os.WriteFile(keyFile, certificates.PrivateKey, 0600); err != nil {
		log.Fatalf("Failed to save private key: %v", err)
	}

	fmt.Printf("Certificate obtained successfully for %v\n", certificates.Domain)
	fmt.Printf("Certificate saved to: %s\n", certFile)
	fmt.Printf("Private key saved to: %s\n", keyFile)
}

func loadOrCreateAccountKey(keyPath string) (crypto.PrivateKey, error) {
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		return key, saveAccountKey(keyPath, key)
	}

	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(keyBytes)
	return x509.ParseECPrivateKey(block.Bytes)
}

func saveAccountKey(keyPath string, key *ecdsa.PrivateKey) error {
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}

	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}
	return os.WriteFile(keyPath, pem.EncodeToMemory(block), 0600)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}