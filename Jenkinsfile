pipeline {
    agent any

    stages {
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

        stage('Analyze Results') {
            steps {
                sh '''
                    cat semgrep-report.json
                '''
            }
        }

        stage('Archive') {
            steps {
                archiveArtifacts artifacts: 'semgrep-report.json'
            }
        }
    }
}
