// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0
//
// This code is used to retrieve values from AWS Secrets Manager and to output the
// decrypted values for conversion into Lambda Environmental Variables.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"encoding/json"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/config"
)

// Constants for default values if none are supplied
const DEFAULT_TIMEOUT = 5000
const DEFAULT_REGION = "ap-southeast-1"
const DEFAULT_SESSION = "lambda_get_secret_as_env"

type secretIdList []string

var (
	region      string
	secretIds   secretIdList
	roleArn     string
	timeout     int
	sessionName string
)

// The main function will pull command line arg and retrieve the secret.  The resulting
// secret will be dumped as JSON to the output
func main() {

	// Get all of the command line data and perform the necessary validation
	getCommandParams()

	// Setup a new context to allow for limited execution time for API calls with a default of 200 milliseconds
	ctx, cancel := context.WithTimeout(context.TODO(), time.Duration(timeout)*time.Millisecond)
	defer cancel()

	// Load the config
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region), config.WithRetryer(func() aws.Retryer {
		// NopRetryer is used here in a global context to avoid retries on API calls
		return retry.AddWithMaxAttempts(aws.NopRetryer{}, 1)
	}))

	if err != nil {
		panic("configuration error " + err.Error())
	}

	// Assume a role to retreive the parameter
	role, err := AttemptAssumeRole(ctx, cfg)

	if err != nil {
		panic("Failed to assume role due to error " + err.Error())
	}

	// variable to output
	var dat map[string]interface{}

	for _, s := range secretIds {
		// Get the secret
		result, err := GetSecret(ctx, cfg, role, s)

		if err != nil {
			panic("Failed to retrieve secret due to error " + err.Error())
		}

		// Convert the secret to JSON
		if err := json.Unmarshal([]byte(*result.SecretString), &dat); err != nil {
			fmt.Println("Failed to convert Secret to JSON")
			fmt.Println(err)
			panic(err)
		}
	}

	// Get the secret value and dump the output in a manner that a shell script can read the
	// data from the output
	for key, value := range dat {
		fmt.Printf("%s|%s\n", key, value)
	}
}

// String is the method to format the flag's value, part of the flag.Value interface.
// The String method's output will be used in diagnostics.
func (s *secretIdList) String() string {
	return fmt.Sprint(*s)
}

// Set is the method to set the flag value, part of the flag.Value interface.
// Set's argument is a string to be parsed to set the flag.
// It's a comma-separated list, so we split it.
func (s *secretIdList) Set(value string) error {
	// If we wanted to allow the flag to be set multiple times,
	// accumulating values, we would delete this if statement.
	// That would permit usages such as
	//	-deltaT 10s -deltaT 15s
	// and other combinations.
	if len(*s) > 0 {
		return errors.New("Secret Ids flag already set")
	}
	for _, id := range strings.Split(value, ",") {
		*s = append(*s, id)
	}
	return nil
}

func getCommandParams() {
	// Setup command line args
	flag.StringVar(&region, "r", DEFAULT_REGION, "The Amazon Region to use")
	flag.Var(&secretIds, "s", "Comma separated list of secret ids to access")
	flag.StringVar(&roleArn, "a", "", "The ARN for the role to assume for Secret Access")
	flag.IntVar(&timeout, "t", 5000, "The amount of time to wait for any API call")
	flag.StringVar(&sessionName, "n", DEFAULT_SESSION, "The name of the session for AWS STS")

	// Parse all of the command line args into the specified vars with the defaults
	flag.Parse()

	// Verify that the correct number of args were supplied
	if len(region) == 0 || len(secretIds) == 0 {
		flag.PrintDefaults()
		panic("You must supply a region and secret ids.  -r REGION -s SECRET-IDS [-a ARN for ROLE -t TIMEOUT IN MILLISECONDS -n SESSION NAME]")
	}
}

// This function will attempt to assume the supplied role and return either an error or the assumed role
func AttemptAssumeRole(ctx context.Context, cfg aws.Config) (*sts.AssumeRoleOutput, error) {
	if len(roleArn) <= 0 {
		return nil, nil
	}

	client := sts.NewFromConfig(cfg)

	return client.AssumeRole(ctx,
		&sts.AssumeRoleInput{
			RoleArn:         &roleArn,
			RoleSessionName: &sessionName,
		},
	)
}

// This function will return the descrypted version of the Secret from Secret Manager using the supplied
// assumed role to interact with Secret Manager.  This function will return either an error or the
// retrieved and decrypted secret.
func GetSecret(ctx context.Context, cfg aws.Config, assumedRole *sts.AssumeRoleOutput, secretId string) (*secretsmanager.GetSecretValueOutput, error) {

	if assumedRole != nil {
		client := secretsmanager.NewFromConfig(cfg, func(o *secretsmanager.Options) {
			o.Credentials = aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(*assumedRole.Credentials.AccessKeyId, *assumedRole.Credentials.SecretAccessKey, *assumedRole.Credentials.SessionToken))
		})
		return client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretId),
		})
	} else {
		client := secretsmanager.NewFromConfig(cfg)
		return client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
			SecretId: aws.String(secretId),
		})
	}
}
