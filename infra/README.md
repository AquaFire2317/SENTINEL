# AWS Deployment Skeleton

The application is fully runnable locally. This directory is reserved for the
CDK stacks from the approved architecture:

- DynamoDB and S3 data stack
- Lambda compute stack
- Step Functions workflow stack
- API Gateway and CloudFront frontend stack

The AWS SDK adapters in `backend/sentinel/persistence` and
`backend/sentinel/orchestration` are dependency-gated and accept injected
clients for unit testing.
