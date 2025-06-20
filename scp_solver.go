package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

type SCPSolver struct {
	host        string
	user        string
	keyPath     string
	webrootPath string
	sshClient   *ssh.Client
}

func NewSCPSolver(host, user, keyPath, webrootPath string) *SCPSolver {
	return &SCPSolver{
		host:        host,
		user:        user,
		keyPath:     keyPath,
		webrootPath: webrootPath,
	}
}

// Present implements the challenge.Provider interface
func (s *SCPSolver) Present(domain, token, keyAuth string) error {
	// Connect to SSH
	if err := s.connect(); err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}

	// Properly log any errors from Close
	defer func() {
		if err := s.sshClient.Close(); err != nil {
			log.Printf("Error closing SSH client: %v", err)
		}
	}()

	// Create remote directory - fix double slash issue
	webrootPath := s.webrootPath
	if len(webrootPath) > 0 && webrootPath[len(webrootPath)-1] == '/' {
		webrootPath = webrootPath[:len(webrootPath)-1]
	}

	// Use the standard ACME challenge path
	remotePath := webrootPath + "/.well-known/acme-challenge"
	log.Printf("Creating remote directory: %s", remotePath)
	if err := s.createRemoteDir(remotePath); err != nil {
		return fmt.Errorf("failed to create remote directory: %w", err)
	}

	// Upload challenge file
	remoteFile := remotePath + "/" + token
	log.Printf("Uploading challenge file to: %s", remoteFile)
	log.Printf("Challenge content: %s", keyAuth)
	if err := s.uploadFile(remoteFile, keyAuth); err != nil {
		return fmt.Errorf("failed to upload challenge file: %w", err)
	}

	// Set proper permissions for web server access
	if err := s.setPermissions(remotePath, remoteFile); err != nil {
		log.Printf("Warning: Failed to set permissions: %v", err)
	}

	// Verify file was created
	if err := s.verifyFile(remoteFile); err != nil {
		return fmt.Errorf("failed to verify challenge file: %w", err)
	}

	// Test HTTP accessibility
	if err := s.testHTTPAccess(domain, token); err != nil {
		log.Printf("Warning: HTTP test failed: %v", err)
	}

	return nil
}

// CleanUp implements the challenge.Provider interface
func (s *SCPSolver) CleanUp(domain, token, keyAuth string) error {
	if err := s.connect(); err != nil {
		return fmt.Errorf("SSH connection failed: %w", err)
	}

	// Properly log any errors from Close
	defer func() {
		if err := s.sshClient.Close(); err != nil {
			log.Printf("Error closing SSH client: %v", err)
		}
	}()

	// Remove challenge file - fix double slash issue
	webrootPath := s.webrootPath
	if len(webrootPath) > 0 && webrootPath[len(webrootPath)-1] == '/' {
		webrootPath = webrootPath[:len(webrootPath)-1]
	}

	// Use the standard ACME challenge path
	remoteFile := webrootPath + "/.well-known/acme-challenge/" + token
	log.Printf("Cleaning up file: %s", remoteFile)
	session, err := s.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}

	// Properly log any errors from Close
	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("Error closing SSH session: %v", err)
		}
	}()

	return session.Run(fmt.Sprintf("rm -f %s", remoteFile))
}

func (s *SCPSolver) connect() error {
	key, err := os.ReadFile(s.keyPath)
	if err != nil {
		return fmt.Errorf("failed to read SSH key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return fmt.Errorf("failed to parse SSH key: %w", err)
	}

	config := &ssh.ClientConfig{
		User: s.user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	s.sshClient, err = ssh.Dial("tcp", s.host+":22", config)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %w", err)
	}
	return nil
}

func (s *SCPSolver) createRemoteDir(path string) error {
	session, err := s.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}

	// Properly log any errors from Close
	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("Error closing SSH session: %v", err)
		}
	}()

	return session.Run(fmt.Sprintf("mkdir -p %s", path))
}

func (s *SCPSolver) uploadFile(remotePath, content string) error {
	session, err := s.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}

	// Properly log any errors from Close
	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("Error closing SSH session: %v", err)
		}
	}()

	// Use printf to avoid issues with special characters in content
	cmd := fmt.Sprintf("printf '%%s' '%s' > %s", content, remotePath)
	log.Printf("Executing command: %s", cmd)

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		log.Printf("Command output: %s", string(output))
		return fmt.Errorf("command failed: %w, output: %s", err, string(output))
	}

	return nil
}

func (s *SCPSolver) verifyFile(remotePath string) error {
	session, err := s.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}

	// Properly log any errors from Close
	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("Error closing SSH session: %v", err)
		}
	}()

	cmd := fmt.Sprintf("ls -la %s && cat %s", remotePath, remotePath)
	log.Printf("Verifying file with command: %s", cmd)

	output, err := session.CombinedOutput(cmd)
	log.Printf("Verification output: %s", string(output))

	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	return nil
}

func (s *SCPSolver) setPermissions(remotePath, remoteFile string) error {
	session, err := s.sshClient.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}

	// Properly log any errors from Close
	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("Error closing SSH session: %v", err)
		}
	}()

	// Set directory and file permissions for web server access
	cmd := fmt.Sprintf("chmod 755 %s && chmod 644 %s", remotePath, remoteFile)
	log.Printf("Setting permissions: %s", cmd)

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		log.Printf("Permission command output: %s", string(output))
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	return nil
}

func (s *SCPSolver) testHTTPAccess(domain, token string) error {
	url := fmt.Sprintf("https://%s/.well-known/acme-challenge/%s", domain, token)
	log.Printf("Testing HTTP access: %s", url)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}

	// Properly log any errors from Close
	defer func() {
		if resp.Body != nil {
			if err := resp.Body.Close(); err != nil {
				log.Printf("Error closing HTTP response body: %v", err)
			}
		}
	}()

	log.Printf("HTTP response status: %d", resp.StatusCode)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challenge file not accessible via HTTP, status code: %d", resp.StatusCode)
	}

	return nil
}
