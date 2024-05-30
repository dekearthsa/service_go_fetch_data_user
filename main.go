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
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"github.com/golang-jwt/jwt/v4"
)

type DBdata struct {
	AuthStatus bool     `json:"authStatus"`
	Email      string   `json:"email"`
	IsProduct  []string `json:"isProduct"`
	Tenan      string   `json:"tenan"`
	Type       string   `json:"type"`
}

type Payload struct {
	UserID     string   `json:"userID"`
	Email      string   `json:"email"`
	FristName  string   `json:"fristName"`
	LastName   string   `json:"lastName"`
	PlantName  string   `json:"plantName"`
	LineUserId string   `json:"lineUserId"`
	UserTenan  string   `json:"userTenan"`
	UserType   string   `json:"userType"`
	Tel        string   `json:"tel"`
	IsProduct  []string `json:"isProduct"`
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

func ValidateToken(tokens string) (int, string, error) {
	var REGION = "ap-southeast-1"
	var BUCKET = "cdk-hnb659fds-assets-058264531773-ap-southeast-1"
	var KEYFILE = "token.txt"
	setKey, err := getFileFromS3(BUCKET, KEYFILE, REGION)
	jwtKey := []byte(setKey)
	if err != nil {
		return 500, "Internal server error", err
	}
	tokenString := strings.TrimPrefix(tokens, "Bearer ")
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		// fmt.Println("err ====> ", err)
		if err == jwt.ErrSignatureInvalid {
			return 401, "unauthorized", err
		}
		return 401, "unauthorized", err
	}

	if !token.Valid {
		return 401, "unauthorized", err
	}

	return 200, claims.Data.Tenan, nil
}

func handler(ctx context.Context, req events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	var tableName = "demo_user_line_id"
	token := req.Headers["authorization"]
	if token == "" {
		return events.APIGatewayProxyResponse{StatusCode: 401, Body: fmt.Sprintf("unauthorized")}, nil
	}
	staus, result, err := ValidateToken(token)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 400, Body: fmt.Sprintf("Invalid request: %s", err)}, err
	}
	if staus != 200 {
		return events.APIGatewayProxyResponse{StatusCode: staus, Body: result}, nil
	}

	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// Create DynamoDB client
	svc := dynamodb.New(sess)
	filt := expression.Name("UserTenan").Equal(expression.Value(result))
	proj := expression.NamesList(expression.Name("Email"),
		expression.Name("CreateDate"),
		expression.Name("FristName"),
		expression.Name("LastName"),
		expression.Name("IsProduct"),
		expression.Name("LineUserId"),
		expression.Name("PlantName"),
		expression.Name("Tel"),
		expression.Name("UserID"),
		expression.Name("UserTenan"),
		expression.Name("UserType"),
	)

	expr, err := expression.NewBuilder().WithFilter(filt).WithProjection(proj).Build()
	if err != nil {
		log.Fatalf("Got error building expression: %s", err)
	}

	params := &dynamodb.ScanInput{
		ExpressionAttributeNames:  expr.Names(),
		ExpressionAttributeValues: expr.Values(),
		FilterExpression:          expr.Filter(),
		ProjectionExpression:      expr.Projection(),
		TableName:                 aws.String(tableName),
	}

	// Make the DynamoDB Query API call
	resultDB, err := svc.Scan(params)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: fmt.Sprintf("Internal server error")}, nil
	}
	// if resultDB.Count == 0 {
	// 	return events.APIGatewayProxyResponse{StatusCode: 200, Body: "No user found"}, nil
	// }

	var payload []Payload
	// err = attributevalue.UnmarshalListOfMaps(resultDB.Items, &payload)
	for _, item := range resultDB.Items {
		el := Payload{}
		err = dynamodbattribute.UnmarshalMap(item, &el)

		if err != nil {
			log.Fatalf("Got error unmarshalling: %s", err)
		}

		var setData = Payload{
			UserID:     el.UserID,
			Email:      el.Email,
			FristName:  el.FristName,
			LastName:   el.LastName,
			PlantName:  el.PlantName,
			LineUserId: el.LineUserId,
			UserTenan:  el.UserTenan,
			UserType:   el.UserType,
			Tel:        el.Tel,
			IsProduct:  el.IsProduct,
		}
		payload = append(payload, setData)
	}
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: fmt.Sprintf("Internal server error")}, nil
	}
	// fmt.Println("payload => ", payload)
	responseBody, err := json.Marshal(payload)
	if err != nil {
		return events.APIGatewayProxyResponse{StatusCode: 500, Body: fmt.Sprintf("Internal server error")}, nil
	}
	return events.APIGatewayProxyResponse{
		StatusCode: 200,
		Body:       string(responseBody),
		Headers:    map[string]string{"Content-Type": "application/json"}}, nil
}

func main() {
	lambda.Start(handler)
}
