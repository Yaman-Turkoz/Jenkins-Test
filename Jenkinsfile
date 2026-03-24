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

        stage('Debug') {
            steps {
                sh '''
                    echo "PWD:"
                    pwd
                    echo "FILES:"
                    ls -la
                    echo "RULES:"
                    ls -la semgrep-rules || true
                '''
            }
        }

        stage('Semgrep Scan') {
            steps {
                sh '''
                    docker run --rm \
                      -v $(pwd):/src \
                      semgrep/semgrep \
                      semgrep scan /src \
                      --config=/src/semgrep-rules --validate\
                      --json \
                      --output=/src/semgrep-report.json
                '''
            }
        }
    }
}
