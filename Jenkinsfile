pipeline {
    agent any

    options {
        skipDefaultCheckout(true)
    }

    stages {
        stage('Clean Workspace') {
            steps {
                deleteDir()
            }
        }
        
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Semgrep Scan') {
            steps {
                sh '''
                    docker run --rm \
                      -v $(pwd):/src \
                      semgrep/semgrep \
                      semgrep scan /src \
                      --config=/src/semgrep-rules \
                      --json \
                      --output=/src/semgrep-report.json
                '''
            }
        }
    }
}
