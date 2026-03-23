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
            agent {
                docker {
                    image 'semgrep/semgrep'
                }
            }
            steps {
                sh '''
                    semgrep scan \
                      --config=auto \
                      --json \
                      --output=semgrep-report.json
                '''
            }
        }
    }
}
