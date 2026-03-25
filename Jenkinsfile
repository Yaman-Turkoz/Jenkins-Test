pipeline {
    agent any


    stages {

        stage('Debug Workspace') {
            steps {
                sh '''
                    echo "WORKSPACE:"
                    echo $WORKSPACE

                    echo "FILES (host):"
                    ls -la $WORKSPACE

                    echo "FILES (container):"
                    docker run --rm \
                        -v $WORKSPACE:/src \
                        semgrep/semgrep \
                        ls -la /src
                '''
            }
        }

        stage('Semgrep Scan') {
            steps {
                script {
                    def exitCode = sh(
                        script: '''
                            docker run --rm \
                                -v $WORKSPACE:/src \
                                -v $WORKSPACE/semgrep-rules/xss.yaml:/xss.yaml:ro \
                                semgrep/semgrep \
                                semgrep scan /src \
                                --config=/xss.yaml \
                                --json > semgrep-report.json
                        ''',
                        returnStatus: true
                    )
        
                    if (exitCode == 0) {
                        echo "Semgrep: Bulgu yok."
                    } else if (exitCode == 7) {
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
