package commands

import (
	b64 "encoding/base64"
	"fmt"
	"log"
	"os"
	"time"

	g3 "github.com/GESkunkworks/gossamer3"
	"github.com/GESkunkworks/gossamer3/helper/credentials"
	"github.com/GESkunkworks/gossamer3/pkg/awsconfig"
	"github.com/GESkunkworks/gossamer3/pkg/cfg"
	"github.com/GESkunkworks/gossamer3/pkg/creds"
	"github.com/GESkunkworks/gossamer3/pkg/flags"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// Login login to ADFS
func Login(loginFlags *flags.LoginExecFlags) error {

	logger := logrus.WithField("command", "login")

	account, err := buildIdpAccount(loginFlags)
	if err != nil {
		return errors.Wrap(err, "error building login details")
	}

	// Load entire shared creds file, if it does not exist, create it and load a blank
	sharedCredsFile, err := awsconfig.LoadCredentialsFile()
	if err != nil {
		return errors.Wrap(err, "error loading credentials file")
	}

	logger.Debug("check if Creds Exist")

	// Try to load profile and see if creds arent expired yet
	awsCreds, err := sharedCredsFile.Load(account.Profile)
	if err != nil && err != awsconfig.ErrCredentialsNotFound {
		return errors.Wrap(err, "error loading credentials")
	}

	// Credentials with that profile already exists
	if awsCreds != nil {
		// Check if creds are expired
		expired := time.Until(awsCreds.Expires) < 0

		// Not expired, and not forcing login, no need to login
		if !expired && !loginFlags.Force {
			log.Println("Credentials are not expired (use --force to login anyways)")
			return nil
		}
	}

	// Get essential login details
	loginDetails, err := resolveLoginDetails(account, loginFlags)
	if err != nil {
		log.Printf("%+v", err)
		os.Exit(1)
	}

	// Validate login details (Make sure URL, Username, and password all exist)
	if err := loginDetails.Validate(); err != nil {
		return errors.Wrap(err, "error validating login details")
	}

	logger.WithField("idpAccount", account).Debug("building provider")

	// Create a samlclient using Ping
	provider, err := g3.NewSAMLClient(account)
	if err != nil {
		return errors.Wrap(err, "error building IdP client")
	}

	log.Printf("Authenticating as %s ...", loginDetails.Username)

	// Auth using provider, get the saml assertion back
	samlAssertion, err := provider.Authenticate(loginDetails)
	if err != nil {
		return errors.Wrap(err, "error authenticating to IdP")
	}

	// If saml assertion is blank, password is incorrect or configuration is incorrect
	if samlAssertion == "" {
		log.Println("Response did not contain a valid SAML assertion")
		log.Println("Please check your username and password is correct")
		log.Println("To see the output follow the instructions in https://github.com/GESkunkworks/gossamer3#debugging-issues-with-idps")
		os.Exit(1)
	}

	// Keychain is not disabled, save creds to keychain
	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.SaveCredentials(loginDetails.URL, loginDetails.Username, loginDetails.Password)
		if err != nil {
			return errors.Wrap(err, "error storing password in keychain")
		}
	}

	// Prompt user for a role after decoding saml assertion and verifying which roles you have access to based on your IDP Account
	role, err := selectAwsRole(samlAssertion, account)
	if err != nil {
		return errors.Wrap(err, "Failed to assume role, please check whether you are permitted to assume the given role for the AWS service")
	}

	log.Println("Selected role:", role.RoleARN)

	// Assume role using IDP account
	awsCreds, err = loginToStsUsingRole(role, account.SessionDuration, samlAssertion, account.Region)
	if err != nil {
		return errors.Wrap(err, "error logging into aws role using saml assertion")
	}

	// Check if a child role is to be assumed
	if loginFlags.AssumeChildRole != "" {
		samlAssertionData, err := b64.StdEncoding.DecodeString(samlAssertion)
		if err != nil {
			return errors.Wrap(err, "error decoding saml assertion")
		}

		// Get the role session name to use in role assumptions
		roleSessionName, err := g3.ExtractRoleSessionName(samlAssertionData)
		if err != nil {
			return errors.Wrap(err, "error extracting role session name")
		}
		roleSessionName = fmt.Sprintf("gossamer3-%s", roleSessionName)

		// Assume child role, overwrite parent creds
		awsCreds, err = assumeRole(awsCreds, loginFlags.AssumeChildRole, roleSessionName, account.Region)
		if err != nil {
			return errors.Wrap(err, "error assuming child role")
		}
	}

	return saveCredentials(account.Profile, awsCreds, sharedCredsFile)
}

func buildIdpAccount(loginFlags *flags.LoginExecFlags) (*cfg.IDPAccount, error) {
	cfgm, err := cfg.NewConfigManager(loginFlags.CommonFlags.ConfigFile)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load configuration")
	}

	account, err := cfgm.LoadIDPAccount(loginFlags.CommonFlags.IdpAccount)
	if err != nil {
		return nil, errors.Wrap(err, "failed to load idp account")
	} else if account == nil {
		return nil, errors.Errorf("idp account %s does not exist", loginFlags.CommonFlags.IdpAccount)
	}

	// update username and hostname if supplied
	flags.ApplyFlagOverrides(loginFlags.CommonFlags, account)

	err = account.Validate()
	if err != nil {
		return nil, errors.Wrap(err, "failed to validate account")
	}

	return account, nil
}

func resolveLoginDetails(account *cfg.IDPAccount, loginFlags *flags.LoginExecFlags) (*creds.LoginDetails, error) {
	loginDetails := &creds.LoginDetails{
		URL:       account.URL,
		Username:  account.Username,
		MFAToken:  loginFlags.CommonFlags.MFAToken,
		MFADevice: account.MFADevice,
		MFAPrompt: account.MFAPrompt,
	}

	log.Printf("Using IDP Account %s to access %s %s", loginFlags.CommonFlags.IdpAccount, account.Provider, account.URL)

	var err error
	if !loginFlags.CommonFlags.DisableKeychain {
		err = credentials.LookupCredentials(loginDetails, account.Provider)
		if err != nil {
			if !credentials.IsErrCredentialsNotFound(err) {
				return nil, errors.Wrap(err, "error loading saved password")
			}
		}
	}

	// log.Printf("%s %s", savedUsername, savedPassword)

	// if you supply a username in a flag it takes precedence
	if loginFlags.CommonFlags.Username != "" {
		loginDetails.Username = loginFlags.CommonFlags.Username
	}

	if loginFlags.CommonFlags.Password != "" {
		loginDetails.Password = loginFlags.CommonFlags.Password
	}

	if loginFlags.CommonFlags.MFADevice != "" {
		loginDetails.MFADevice = loginFlags.CommonFlags.MFADevice
	}

	// log.Printf("loginDetails %+v", loginDetails)

	// if skip prompt was passed just pass back the flag values
	if loginFlags.CommonFlags.SkipPrompt {
		return loginDetails, nil
	}

	err = g3.PromptForLoginDetails(loginDetails, account.Provider)
	if err != nil {
		return nil, errors.Wrap(err, "Error occurred accepting input")
	}

	return loginDetails, nil
}

// Take a decoded saml assertion and extract roles from it
func grabAllAwsRoles(decodedSamlAssertion []byte) ([]*g3.AWSRole, error) {
	roles, err := g3.ExtractAwsRoles(decodedSamlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing aws roles")
	}

	// If no roles are found, exit with an error
	if len(roles) == 0 {
		log.Println("No roles to assume")
		log.Println("Please check you are permitted to assume roles for the AWS service")
		os.Exit(1)
	}

	return g3.ParseAWSRoles(roles)
}

// selectAwsRole takes a saml assertion and configuration and makes the user choose a single AWS role to assume into
func selectAwsRole(samlAssertion string, account *cfg.IDPAccount) (*g3.AWSRole, error) {
	// Decode saml assertion
	data, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding saml assertion")
	}

	// Parse and verify AWS roles from decoded saml assertion
	awsRoles, err := grabAllAwsRoles(data)
	if err != nil {
		return nil, err
	}

	return resolveRole(awsRoles, samlAssertion, account)
}

func resolveRole(awsRoles []*g3.AWSRole, samlAssertion string, account *cfg.IDPAccount) (*g3.AWSRole, error) {
	var role = new(g3.AWSRole)

	// If there is only 1 role, use that one without asking
	// If 0 roles (shouldnt happen), then return an error
	if len(awsRoles) == 1 {
		if account.RoleARN != "" {
			return g3.LocateRole(awsRoles, account.RoleARN)
		}
		return awsRoles[0], nil
	} else if len(awsRoles) == 0 {
		return nil, errors.New("no roles available")
	}

	// TODO: Remove second saml assertion
	samlAssertionData, err := b64.StdEncoding.DecodeString(samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error decoding saml assertion")
	}

	aud, err := g3.ExtractDestinationURL(samlAssertionData)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing destination url")
	}

	awsAccounts, err := g3.ParseAWSAccounts(aud, samlAssertion)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing aws role accounts")
	}
	if len(awsAccounts) == 0 {
		return nil, errors.New("no accounts available")
	}

	g3.AssignPrincipals(awsRoles, awsAccounts)

	if account.RoleARN != "" {
		return g3.LocateRole(awsRoles, account.RoleARN)
	}

	for {
		role, err = g3.PromptForAWSRoleSelection(awsAccounts)
		if err == nil {
			break
		}
		log.Println("error selecting role, try again")
	}

	return role, nil
}

func loginToStsUsingRole(role *g3.AWSRole, sessionDuration int, samlAssertion, region string) (*awsconfig.AWSCredentials, error) {
	sess, err := session.NewSession(&aws.Config{
		Region: &region,
	})
	if err != nil {
		return nil, errors.Wrap(err, "failed to create session")
	}

	// Set user agent handler
	awsconfig.OverrideUserAgent(sess)

	svc := sts.New(sess)

	params := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(role.PrincipalARN), // Required
		RoleArn:         aws.String(role.RoleARN),      // Required
		SAMLAssertion:   aws.String(samlAssertion),     // Required
		DurationSeconds: aws.Int64(int64(sessionDuration)),
	}

	resp, err := svc.AssumeRoleWithSAML(params)
	if err != nil {
		return nil, errors.Wrap(err, "error retrieving STS credentials using SAML")
	}

	return &awsconfig.AWSCredentials{
		AWSAccessKey:     aws.StringValue(resp.Credentials.AccessKeyId),
		AWSSecretKey:     aws.StringValue(resp.Credentials.SecretAccessKey),
		AWSSessionToken:  aws.StringValue(resp.Credentials.SessionToken),
		AWSSecurityToken: aws.StringValue(resp.Credentials.SessionToken),
		PrincipalARN:     aws.StringValue(resp.AssumedRoleUser.Arn),
		Expires:          resp.Credentials.Expiration.Local(),
		Region:           region,
	}, nil
}

func saveCredentials(profile string, awsCreds *awsconfig.AWSCredentials, sharedCredsFile *awsconfig.CredentialsFile) error {
	// Store creds to credentials file in memory
	if err := sharedCredsFile.StoreCreds(profile, awsCreds); err != nil {
		return errors.Wrap(err, "error adding profile to credentials")
	}

	logrus.Debugln("stored credentials to memory")

	// Save credentials file from memory to storage
	if err := sharedCredsFile.SaveFile(); err != nil {
		return errors.Wrap(err, "error storing credentials file")
	}

	logrus.Debugln("stored credentials to disk")

	log.Println("Logged in as:", awsCreds.PrincipalARN)
	log.Println("")
	log.Println("Your new access key pair has been stored in the AWS configuration")
	log.Printf("Note that it will expire at %v", awsCreds.Expires)
	log.Println("To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile", profile, "ec2 describe-instances).")

	return nil
}
