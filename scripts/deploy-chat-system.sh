#!/bin/bash

# AWS Multi-Account Chat System Deployment Script
# This script deploys the complete chat system infrastructure

set -e

# Configuration
MANAGEMENT_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION="us-east-1"
STACK_NAME="AwsChatSystemStack"
ROLE_NAME="ChatSystemReadOnlyRole"

echo "🚀 Starting AWS Multi-Account Chat System Deployment"
echo "Management Account ID: $MANAGEMENT_ACCOUNT_ID"
echo "Region: $REGION"

# Function to check if AWS CLI is configured
check_aws_cli() {
    if ! aws sts get-caller-identity > /dev/null 2>&1; then
        echo "❌ AWS CLI is not configured or credentials are invalid"
        exit 1
    fi
    echo "✅ AWS CLI is configured"
}

# Function to check if CDK is installed
check_cdk() {
    if ! command -v cdk &> /dev/null; then
        echo "❌ AWS CDK is not installed. Please install it with: npm install -g aws-cdk"
        exit 1
    fi
    echo "✅ AWS CDK is installed"
}

# Function to bootstrap CDK if needed
bootstrap_cdk() {
    echo "🔧 Checking CDK bootstrap status..."
    if ! aws cloudformation describe-stacks --stack-name CDKToolkit --region $REGION > /dev/null 2>&1; then
        echo "📦 Bootstrapping CDK..."
        cdk bootstrap aws://$MANAGEMENT_ACCOUNT_ID/$REGION
    else
        echo "✅ CDK is already bootstrapped"
    fi
}

# Function to create cross-account role CloudFormation template
create_cross_account_template() {
    cat > cross-account-role.yaml << EOF
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Cross-account read-only role for AWS Chat System'

Parameters:
  ManagementAccountId:
    Type: String
    Description: Management account ID that will assume this role
    Default: $MANAGEMENT_ACCOUNT_ID

Resources:
  ChatSystemReadOnlyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: $ROLE_NAME
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: !Sub 'arn:aws:iam::\${ManagementAccountId}:root'
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                'sts:ExternalId': 'ChatSystemAccess'
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/ReadOnlyAccess
        - arn:aws:iam::aws:policy/AWSConfigUserAccess
      Policies:
        - PolicyName: ChatSystemAdditionalPermissions
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - ce:GetCostAndUsage
                  - ce:GetUsageReport
                  - ce:GetReservationCoverage
                  - ce:GetReservationPurchaseRecommendation
                  - ce:GetReservationUtilization
                  - ce:ListCostCategoryDefinitions
                  - support:DescribeCases
                  - support:DescribeServices
                  - support:DescribeSeverityLevels
                  - trustedadvisor:Describe*
                Resource: '*'

Outputs:
  RoleArn:
    Description: ARN of the created role
    Value: !GetAtt ChatSystemReadOnlyRole.Arn
    Export:
      Name: !Sub '\${AWS::StackName}-RoleArn'
EOF
}

# Function to deploy cross-account roles
deploy_cross_account_roles() {
    echo "🔐 Deploying cross-account roles..."
    
    # Get list of all accounts in organization
    ACCOUNTS=$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].Id' --output text 2>/dev/null || echo "")
    
    if [ -z "$ACCOUNTS" ]; then
        echo "⚠️  Could not retrieve organization accounts. You may need to deploy roles manually."
        echo "📋 Use the cross-account-role.yaml template to deploy to each member account"
        return
    fi
    
    create_cross_account_template
    
    SUCCESS_COUNT=0
    TOTAL_COUNT=0
    
    for ACCOUNT_ID in $ACCOUNTS; do
        if [ "$ACCOUNT_ID" != "$MANAGEMENT_ACCOUNT_ID" ]; then
            TOTAL_COUNT=$((TOTAL_COUNT + 1))
            echo "📤 Deploying role to account: $ACCOUNT_ID"
            
            # Try to deploy using cross-account access (requires pre-configured profiles)
            if aws cloudformation deploy \
                --template-file cross-account-role.yaml \
                --stack-name ChatSystemCrossAccountRole \
                --capabilities CAPABILITY_NAMED_IAM \
                --parameter-overrides ManagementAccountId=$MANAGEMENT_ACCOUNT_ID \
                --profile account-$ACCOUNT_ID \
                --region $REGION > /dev/null 2>&1; then
                echo "✅ Successfully deployed to account $ACCOUNT_ID"
                SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            else
                echo "⚠️  Failed to deploy to account $ACCOUNT_ID (profile may not exist)"
            fi
        fi
    done
    
    echo "📊 Cross-account role deployment summary:"
    echo "   Successfully deployed: $SUCCESS_COUNT/$TOTAL_COUNT accounts"
    
    if [ $SUCCESS_COUNT -lt $TOTAL_COUNT ]; then
        echo "⚠️  Some deployments failed. You may need to:"
        echo "   1. Configure AWS CLI profiles for each account"
        echo "   2. Manually deploy the cross-account-role.yaml template"
        echo "   3. Ensure you have necessary permissions in each account"
    fi
}

# Function to create CDK app structure
create_cdk_app() {
    if [ ! -f "cdk.json" ]; then
        echo "📁 Creating CDK application structure..."
        
        # Initialize CDK app
        cdk init app --language typescript
        
        # Install additional dependencies
        npm install @aws-cdk/aws-bedrock-alpha
        
        echo "✅ CDK application structure created"
    else
        echo "✅ CDK application already exists"
    fi
}

# Function to deploy main infrastructure
deploy_main_infrastructure() {
    echo "🏗️  Deploying main infrastructure..."
    
    # Build the CDK app
    npm run build
    
    # Deploy the stack
    cdk deploy $STACK_NAME --require-approval never
    
    echo "✅ Main infrastructure deployed successfully"
}

# Function to create sample environment file
create_env_file() {
    if [ ! -f ".env" ]; then
        cat > .env << EOF
# AWS Chat System Configuration
AWS_REGION=$REGION
MANAGEMENT_ACCOUNT_ID=$MANAGEMENT_ACCOUNT_ID
CROSS_ACCOUNT_ROLE_NAME=$ROLE_NAME

# Bedrock Configuration
BEDROCK_MODEL_ID=anthropic.claude-3-sonnet-20240229-v1:0
BEDROCK_REGION=us-east-1

# DynamoDB Configuration
ACCOUNT_INVENTORY_TABLE=ChatSystem-AccountInventory
QUERY_HISTORY_TABLE=ChatSystem-QueryHistory

# API Configuration
API_THROTTLE_RATE=1000
API_BURST_LIMIT=2000

# Security Configuration
SESSION_TIMEOUT_MINUTES=60
MFA_REQUIRED=true
EOF
        echo "✅ Environment configuration file created (.env)"
    fi
}

# Function to display post-deployment instructions
show_post_deployment_instructions() {
    echo ""
    echo "🎉 Deployment completed successfully!"
    echo ""
    echo "📋 Next Steps:"
    echo "1. Configure user authentication in AWS Cognito"
    echo "2. Deploy the frontend application to S3/CloudFront"
    echo "3. Test the system with sample queries"
    echo "4. Set up monitoring and alerting"
    echo ""
    echo "🔗 Useful Resources:"
    echo "- CloudFormation Stack: https://console.aws.amazon.com/cloudformation/home?region=$REGION#/stacks/stackinfo?stackId=$STACK_NAME"
    echo "- API Gateway: https://console.aws.amazon.com/apigateway/home?region=$REGION"
    echo "- Lambda Functions: https://console.aws.amazon.com/lambda/home?region=$REGION"
    echo "- DynamoDB Tables: https://console.aws.amazon.com/dynamodb/home?region=$REGION"
    echo ""
    echo "🧪 Test the system:"
    echo "curl -X POST https://YOUR_API_GATEWAY_URL/query \\"
    echo "  -H 'Content-Type: application/json' \\"
    echo "  -H 'Authorization: Bearer YOUR_JWT_TOKEN' \\"
    echo "  -d '{\"query\": \"Show me all EC2 instances\", \"user_id\": \"test-user\"}'"
    echo ""
}

# Main execution
main() {
    echo "🔍 Running pre-deployment checks..."
    check_aws_cli
    check_cdk
    
    echo "🔧 Setting up infrastructure..."
    bootstrap_cdk
    create_env_file
    create_cdk_app
    
    echo "🚀 Deploying infrastructure..."
    deploy_main_infrastructure
    deploy_cross_account_roles
    
    show_post_deployment_instructions
}

# Handle script interruption
trap 'echo "❌ Deployment interrupted"; exit 1' INT TERM

# Run main function
main "$@"
