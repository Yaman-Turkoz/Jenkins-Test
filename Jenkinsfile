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
                script {
                    def hostWorkspace = env.WORKSPACE.replace(
                        '/var/jenkins_home',
                        env.HOST_JENKINS_HOME
                    )
                    def exitCode = sh(
                        script: """
                            docker run --rm \\
                              -v ${hostWorkspace}:/src \\
                              semgrep/semgrep \\
                              semgrep scan /src \\
                              --config=/src/semgrep-rules/xss.yaml \\
                              --json > semgrep-report.json
                        """,
                        returnStatus: true
                    )
                    if (exitCode == 0) {
                        echo "Semgrep: Bulgu yok."
                    } else if (exitCode == 1 || exitCode == 7) {
                        echo "Semgrep: Güvenlik bulguları tespit edildi!"
                        unstable("Semgrep bulguları mevcut.")
                    } else {
                        error("Semgrep beklenmedik hatayla çıktı: ${exitCode}")
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true
        }
    }
}
