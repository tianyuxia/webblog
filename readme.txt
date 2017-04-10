Current Project is deployed at 

https://onyx-window-161320.appspot.com/

The program can be ran both locally and deployed publicly

local:

- Using git bash, traverse to the directory where Blog Project is located
- Intall gcloud following the instructions at https://cloud.google.com/sdk/downloads
- In the Blog Project directory, enter the following command: dev_appserver.py app.yaml
- The locally compiled webpage can be used at localhost:8080

public

- Using git bash, traverse to the directory where Blog Project is located
- Intall gcloud following the instructions at https://cloud.google.com/sdk/downloads
- In the Blog Project directory, enter the following command: gcloud app deploy
- The publicly hosted webpage can be accessed by the following command: gcloud app browse
