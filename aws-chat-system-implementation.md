# AWS Multi-Account Chat Query System - Technical Implementation Guide

## Infrastructure as Code Templates

### 1. Cross-Account IAM Role Setup

#### Management Account - Orchestrator Role
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "lambda.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

#### Management Account - Orchestrator Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:AssumeRole"
      ],
      "Resource": "arn:aws:iam::*:role/ChatSystemReadOnlyRole"
    },
    {
      "Effect": "Allow",
      "Action": [
        "organizations:ListAccounts",
        "organizations:DescribeAccount",
        "organizations:ListOrganizationalUnitsForParent"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:Query",
        "dynamodb:Scan",
        "dynamodb:UpdateItem"
      ],
      "Resource": [
        "arn:aws:dynamodb:*:*:table/ChatSystem*"
      ]
    }
  ]
}
```

#### Member Account - Read-Only Role Policy
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:GetBucket*",
        "s3:ListBucket*",
        "s3:ListAllMyBuckets",
        "rds:Describe*",
        "lambda:List*",
        "lambda:Get*",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:ListMetrics",
        "cloudwatch:GetMetricData",
        "config:GetResourceConfigHistory",
        "config:ListDiscoveredResources",
        "config:GetComplianceDetailsByResource",
        "ce:GetCostAndUsage",
        "ce:GetUsageReport",
        "ce:GetReservationCoverage",
        "iam:GetRole",
        "iam:ListRoles",
        "iam:GetPolicy",
        "iam:ListPolicies",
        "cloudformation:DescribeStacks",
        "cloudformation:ListStacks",
        "elasticloadbalancing:Describe*",
        "autoscaling:Describe*",
        "route53:List*",
        "route53:Get*"
      ],
      "Resource": "*"
    }
  ]
}
```

### 2. AWS CDK Infrastructure Stack

```typescript
import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as s3 from 'aws-cdk-lib/aws-s3';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';

export class AwsChatSystemStack extends cdk.Stack {
  constructor(scope: cdk.App, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // DynamoDB Tables
    const accountInventoryTable = new dynamodb.Table(this, 'AccountInventory', {
      tableName: 'ChatSystem-AccountInventory',
      partitionKey: { name: 'accountId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'resourceType', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.ON_DEMAND,
      pointInTimeRecovery: true,
      encryption: dynamodb.TableEncryption.AWS_MANAGED
    });

    const queryHistoryTable = new dynamodb.Table(this, 'QueryHistory', {
      tableName: 'ChatSystem-QueryHistory',
      partitionKey: { name: 'userId', type: dynamodb.AttributeType.STRING },
      sortKey: { name: 'timestamp', type: dynamodb.AttributeType.STRING },
      billingMode: dynamodb.BillingMode.ON_DEMAND,
      timeToLiveAttribute: 'ttl'
    });

    // Cognito User Pool
    const userPool = new cognito.UserPool(this, 'ChatSystemUserPool', {
      userPoolName: 'aws-chat-system-users',
      selfSignUpEnabled: false,
      signInAliases: { email: true },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true
      },
      mfa: cognito.Mfa.REQUIRED,
      mfaSecondFactor: {
        sms: true,
        otp: true
      }
    });

    // Lambda Functions
    const queryOrchestratorFunction = new lambda.Function(this, 'QueryOrchestrator', {
      runtime: lambda.Runtime.PYTHON_3_11,
      handler: 'orchestrator.handler',
      code: lambda.Code.fromAsset('lambda/orchestrator'),
      timeout: cdk.Duration.minutes(5),
      memorySize: 1024,
      environment: {
        ACCOUNT_INVENTORY_TABLE: accountInventoryTable.tableName,
        QUERY_HISTORY_TABLE: queryHistoryTable.tableName,
        BEDROCK_MODEL_ID: 'anthropic.claude-3-sonnet-20240229-v1:0'
      }
    });

    // Grant permissions
    accountInventoryTable.grantReadWriteData(queryOrchestratorFunction);
    queryHistoryTable.grantReadWriteData(queryOrchestratorFunction);

    // Cross-account assume role permission
    queryOrchestratorFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['sts:AssumeRole'],
      resources: ['arn:aws:iam::*:role/ChatSystemReadOnlyRole']
    }));

    // Bedrock permissions
    queryOrchestratorFunction.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: [
        'bedrock:InvokeModel',
        'bedrock:InvokeModelWithResponseStream'
      ],
      resources: ['*']
    }));

    // API Gateway
    const api = new apigateway.RestApi(this, 'ChatSystemApi', {
      restApiName: 'AWS Chat System API',
      description: 'API for AWS multi-account chat query system',
      defaultCorsPreflightOptions: {
        allowOrigins: apigateway.Cors.ALL_ORIGINS,
        allowMethods: apigateway.Cors.ALL_METHODS,
        allowHeaders: ['Content-Type', 'Authorization']
      }
    });

    const queryResource = api.root.addResource('query');
    queryResource.addMethod('POST', new apigateway.LambdaIntegration(queryOrchestratorFunction));

    // S3 Bucket for frontend hosting
    const frontendBucket = new s3.Bucket(this, 'FrontendBucket', {
      bucketName: `aws-chat-system-frontend-${this.account}`,
      websiteIndexDocument: 'index.html',
      publicReadAccess: false,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL
    });

    // CloudFront Distribution
    const distribution = new cloudfront.CloudFrontWebDistribution(this, 'Distribution', {
      originConfigs: [{
        s3OriginSource: {
          s3BucketSource: frontendBucket
        },
        behaviors: [{ isDefaultBehavior: true }]
      }]
    });
  }
}
```

### 3. Lambda Function Implementation

#### Query Orchestrator Function
```python
import json
import boto3
import logging
from typing import Dict, List, Any
from datetime import datetime, timedelta
import re

logger = logging.getLogger()
logger.setLevel(logging.INFO)

class AWSChatOrchestrator:
    def __init__(self):
        self.sts_client = boto3.client('sts')
        self.organizations_client = boto3.client('organizations')
        self.dynamodb = boto3.resource('dynamodb')
        self.bedrock_client = boto3.client('bedrock-runtime')
        
        self.account_table = self.dynamodb.Table('ChatSystem-AccountInventory')
        self.query_table = self.dynamodb.Table('ChatSystem-QueryHistory')
    
    def parse_natural_language_query(self, query: str) -> Dict[str, Any]:
        """Parse natural language query using Amazon Bedrock"""
        
        prompt = f"""
        Parse the following AWS query and extract:
        1. AWS services mentioned
        2. Resource types
        3. Filters (region, tags, etc.)
        4. Query intent (list, describe, count, etc.)
        5. Time range if specified
        
        Query: {query}
        
        Respond in JSON format with keys: services, resources, filters, intent, time_range
        """
        
        try:
            response = self.bedrock_client.invoke_model(
                modelId='anthropic.claude-3-sonnet-20240229-v1:0',
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            result = json.loads(response['body'].read())
            return json.loads(result['content'][0]['text'])
            
        except Exception as e:
            logger.error(f"Error parsing query: {str(e)}")
            return self._fallback_parse(query)
    
    def _fallback_parse(self, query: str) -> Dict[str, Any]:
        """Fallback parsing using regex patterns"""
        services = []
        resources = []
        
        # Common AWS service patterns
        service_patterns = {
            'ec2': r'\b(ec2|instance|server|vm)\b',
            's3': r'\b(s3|bucket|storage)\b',
            'rds': r'\b(rds|database|db)\b',
            'lambda': r'\b(lambda|function)\b',
            'iam': r'\b(iam|role|policy|user)\b'
        }
        
        for service, pattern in service_patterns.items():
            if re.search(pattern, query.lower()):
                services.append(service)
        
        return {
            'services': services,
            'resources': resources,
            'filters': {},
            'intent': 'list',
            'time_range': None
        }
    
    def get_organization_accounts(self) -> List[Dict[str, str]]:
        """Get all accounts in the organization"""
        try:
            response = self.organizations_client.list_accounts()
            return [
                {
                    'id': account['Id'],
                    'name': account['Name'],
                    'email': account['Email'],
                    'status': account['Status']
                }
                for account in response['Accounts']
                if account['Status'] == 'ACTIVE'
            ]
        except Exception as e:
            logger.error(f"Error getting organization accounts: {str(e)}")
            return []
    
    def assume_cross_account_role(self, account_id: str) -> boto3.Session:
        """Assume role in target account"""
        role_arn = f"arn:aws:iam::{account_id}:role/ChatSystemReadOnlyRole"
        
        try:
            response = self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName=f"ChatSystem-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            )
            
            credentials = response['Credentials']
            return boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
        except Exception as e:
            logger.error(f"Error assuming role in account {account_id}: {str(e)}")
            return None
    
    def query_ec2_resources(self, session: boto3.Session, filters: Dict) -> List[Dict]:
        """Query EC2 resources in the given session"""
        ec2_client = session.client('ec2')
        resources = []
        
        try:
            # Get EC2 instances
            response = ec2_client.describe_instances()
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    resources.append({
                        'type': 'EC2Instance',
                        'id': instance['InstanceId'],
                        'state': instance['State']['Name'],
                        'instance_type': instance['InstanceType'],
                        'launch_time': instance['LaunchTime'].isoformat(),
                        'tags': {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    })
        except Exception as e:
            logger.error(f"Error querying EC2 resources: {str(e)}")
        
        return resources
    
    def query_s3_resources(self, session: boto3.Session, filters: Dict) -> List[Dict]:
        """Query S3 resources in the given session"""
        s3_client = session.client('s3')
        resources = []
        
        try:
            response = s3_client.list_buckets()
            for bucket in response['Buckets']:
                # Get bucket details
                try:
                    location = s3_client.get_bucket_location(Bucket=bucket['Name'])
                    region = location['LocationConstraint'] or 'us-east-1'
                    
                    # Check if bucket is public
                    try:
                        acl = s3_client.get_bucket_acl(Bucket=bucket['Name'])
                        is_public = any(
                            grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers'
                            for grant in acl['Grants']
                        )
                    except:
                        is_public = False
                    
                    resources.append({
                        'type': 'S3Bucket',
                        'name': bucket['Name'],
                        'creation_date': bucket['CreationDate'].isoformat(),
                        'region': region,
                        'is_public': is_public
                    })
                except Exception as e:
                    logger.warning(f"Error getting details for bucket {bucket['Name']}: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Error querying S3 resources: {str(e)}")
        
        return resources
    
    def execute_query(self, parsed_query: Dict, accounts: List[str] = None) -> Dict:
        """Execute the parsed query across specified accounts"""
        results = {}
        
        if not accounts:
            accounts = [acc['id'] for acc in self.get_organization_accounts()]
        
        for account_id in accounts:
            session = self.assume_cross_account_role(account_id)
            if not session:
                continue
            
            account_results = []
            
            # Query based on services mentioned
            for service in parsed_query.get('services', []):
                if service == 'ec2':
                    account_results.extend(
                        self.query_ec2_resources(session, parsed_query.get('filters', {}))
                    )
                elif service == 's3':
                    account_results.extend(
                        self.query_s3_resources(session, parsed_query.get('filters', {}))
                    )
            
            if account_results:
                results[account_id] = account_results
        
        return results
    
    def generate_response(self, query: str, results: Dict) -> str:
        """Generate natural language response using Bedrock"""
        
        # Summarize results
        total_resources = sum(len(resources) for resources in results.values())
        
        prompt = f"""
        Generate a natural language response for the AWS query: "{query}"
        
        Results summary:
        - Total accounts queried: {len(results)}
        - Total resources found: {total_resources}
        
        Detailed results:
        {json.dumps(results, indent=2, default=str)}
        
        Provide a clear, concise summary of the findings.
        """
        
        try:
            response = self.bedrock_client.invoke_model(
                modelId='anthropic.claude-3-sonnet-20240229-v1:0',
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 2000,
                    "messages": [{"role": "user", "content": prompt}]
                })
            )
            
            result = json.loads(response['body'].read())
            return result['content'][0]['text']
            
        except Exception as e:
            logger.error(f"Error generating response: {str(e)}")
            return f"Found {total_resources} resources across {len(results)} accounts."

def handler(event, context):
    """Lambda handler function"""
    try:
        orchestrator = AWSChatOrchestrator()
        
        # Parse request
        body = json.loads(event['body'])
        query = body.get('query', '')
        user_id = body.get('user_id', 'anonymous')
        
        # Log query
        logger.info(f"Processing query from user {user_id}: {query}")
        
        # Parse natural language query
        parsed_query = orchestrator.parse_natural_language_query(query)
        
        # Execute query
        results = orchestrator.execute_query(parsed_query)
        
        # Generate response
        response_text = orchestrator.generate_response(query, results)
        
        # Store query history
        orchestrator.query_table.put_item(
            Item={
                'userId': user_id,
                'timestamp': datetime.now().isoformat(),
                'query': query,
                'results_count': sum(len(r) for r in results.values()),
                'ttl': int((datetime.now() + timedelta(days=30)).timestamp())
            }
        )
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'response': response_text,
                'results': results,
                'query_id': f"{user_id}-{datetime.now().strftime('%Y%m%d%H%M%S')}"
            })
        }
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': 'Internal server error',
                'message': str(e)
            })
        }
```

## Deployment Instructions

### 1. Prerequisites Setup
```bash
# Install AWS CDK
npm install -g aws-cdk

# Install dependencies
npm install

# Bootstrap CDK (if not done before)
cdk bootstrap
```

### 2. Deploy Infrastructure
```bash
# Deploy the main stack
cdk deploy AwsChatSystemStack

# Deploy cross-account roles to all member accounts
./scripts/deploy-cross-account-roles.sh
```

### 3. Configure Member Accounts
```bash
#!/bin/bash
# deploy-cross-account-roles.sh

MANAGEMENT_ACCOUNT_ID="123456789012"
ROLE_NAME="ChatSystemReadOnlyRole"

# Get list of all accounts in organization
ACCOUNTS=$(aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].Id' --output text)

for ACCOUNT_ID in $ACCOUNTS; do
    if [ "$ACCOUNT_ID" != "$MANAGEMENT_ACCOUNT_ID" ]; then
        echo "Deploying role to account: $ACCOUNT_ID"
        
        # Create CloudFormation template for the role
        cat > /tmp/cross-account-role.yaml << EOF
AWSTemplateFormatVersion: '2010-09-09'
Description: 'Cross-account read-only role for AWS Chat System'

Resources:
  ChatSystemReadOnlyRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: ${ROLE_NAME}
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              AWS: arn:aws:iam::${MANAGEMENT_ACCOUNT_ID}:root
            Action: sts:AssumeRole
            Condition:
              StringEquals:
                'sts:ExternalId': 'ChatSystemAccess'
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/ReadOnlyAccess
        - arn:aws:iam::aws:policy/AWSConfigUserAccess
EOF

        # Deploy using cross-account access
        aws cloudformation deploy \
            --template-file /tmp/cross-account-role.yaml \
            --stack-name ChatSystemCrossAccountRole \
            --capabilities CAPABILITY_NAMED_IAM \
            --profile account-${ACCOUNT_ID} || echo "Failed to deploy to account $ACCOUNT_ID"
    fi
done
```

This comprehensive architecture and implementation guide provides you with a production-ready AWS multi-account chat query system. The solution includes proper security controls, scalability features, and a user-friendly interface for querying AWS resources across your entire organization.
