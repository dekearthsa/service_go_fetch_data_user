package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/golang-jwt/jwt"
)

type DBdata struct {
	AuthStatus bool     `json:"authStatus"`
	Email      string   `json:"email"`
	IsProduct  []string `json:"isProduct"`
	Tenan      string   `json:"tenan"`
	Type       string   `json:"type"`
}

type Claims struct {
	Data DBdata `json:"data"`
	jwt.RegisteredClaims
}

func getFileFromS3(bucket, key string, region string) (string, error) {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithRegion(region))
	if err != nil {
		return "", fmt.Errorf("unable to load SDK config, %v", err)
	}

	client := s3.NewFromConfig(cfg)

	getObjectInput := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	result, err := client.GetObject(context.TODO(), getObjectInput)
	if err != nil {
		return "", fmt.Errorf("failed to get file from S3, %v", err)
	}
	defer result.Body.Close()

	body, err := io.ReadAll(result.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read file content, %v", err)
	}

	return string(body), nil
}

func ValidateToken(tokens string) (events.APIGatewayProxyResponse, error) {
	var REGION = "ap-southeast-1"
	var BUCKET = "cdk-hnb659fds-assets-058264531773-ap-southeast-1"
	var KEYFILE = "token.txt"
	setKey, err := getFileFromS3(BUCKET, KEYFILE, REGION)
	jwtKey := []byte(setKey)
	if err != nil {
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "Internal server error",
		}, err
	}
	fmt.Println("tokens => ", tokens)
	tokenString := strings.TrimPrefix(tokens, "Bearer ")
	fmt.Println("tokenString => ", tokenString)
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	fmt.Println("token => ", token)
	fmt.Println("claims => ", claims)

	if err != nil {
		fmt.Println("err ====> ", err)
		if err == jwt.ErrSignatureInvalid {
			return events.APIGatewayProxyResponse{
				StatusCode: 401,
				Body:       "Invalid token signature",
			}, nil
		}
		return events.APIGatewayProxyResponse{
			StatusCode: 400,
			Body:       "Could not parse token",
		}, nil
	}

	if !token.Valid {
		return events.APIGatewayProxyResponse{
			StatusCode: 401,
			Body:       "Invalid token",
		}, nil
	}

	// Create a response with the claims
	respBody, err := json.Marshal(claims)
	if err != nil {
		log.Println("Error creating response:", err)
		return events.APIGatewayProxyResponse{
			StatusCode: 500,
			Body:       "Internal server error",
		}, nil
	}

	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(respBody),
	}, nil
}

func handler(ctx context.Context) (string, error) {
	return "", nil
}

func main() {
	lambda.Start(handler)
}
