pipeline {
    agent {
        docker {
            image 'semgrep/semgrep'
            args '-v /var/run/docker.sock:/var/run/docker.sock'
        }
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Semgrep Scan') {
            steps {
                sh '''
                    semgrep scan --config=auto . \
                    --json --output=semgrep-report.json
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
