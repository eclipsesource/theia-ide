# Commands

```sh
## Prerequisite: Authenticate with Google Cloud

## change to terraform directory
cd .terraform

## initial setup / sync state with remote location
GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token) terraform init

## apply changes
GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token) terraform apply

# Troubleshooting

## Unlock remote storage
GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token) terraform force-unlock <ID of the Lock Info>

## Import Browser Flow (find out id by changing something on this flow and checking the network tab in browser)
## https://theia-ide-preview.eclipsesource-munich.com/keycloak/admin/master/console/#/TheiaCloud/authentication -> browser flow -> change e.g. identity provider redirector -> inspect network
GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token) terraform import keycloak_authentication_execution.browser TheiaCloud/browser/0aac893f-210e-4183-a649-b70753868ede

## Inspect browser flow to fill out state in main.tf
GOOGLE_OAUTH_ACCESS_TOKEN=$(gcloud auth print-access-token) terraform state show keycloak_authentication_execution.browser
```
