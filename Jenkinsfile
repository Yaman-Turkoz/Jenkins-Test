pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Semgrep Scan') {
            steps {
                script {
                    sh '''
                        docker run --rm \
                          -v $(pwd):/src \
                          returntocorp/semgrep \
                          semgrep --config=auto /src \
                          --json --output=/src/semgrep-results.json \
                          || true
                    '''
                }
            }
        }

        stage('Print Results') {
            steps {
                sh 'cat semgrep-results.json'
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'semgrep-results.json', allowEmptyArchive: true
        }
    }
}
