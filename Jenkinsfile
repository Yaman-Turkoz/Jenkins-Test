pipeline {
    agent any

    stages {
        stage('Checkout') {
            steps {
                git 'https://github.com/your-repo.git'
            }
        }

        stage('Semgrep Scan') {
            steps {
                script {
                    docker.image('semgrep/semgrep').inside {
                        sh """
                        semgrep scan --config=auto
                        """
                    }
                }
            }
        }
    }
}
