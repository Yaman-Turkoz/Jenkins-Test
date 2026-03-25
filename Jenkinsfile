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
                    sh """
                        docker run --rm \\
                          -v ${hostWorkspace}:/src \\
                          semgrep/semgrep \\
                          semgrep scan /src \\
                          --config=/src/semgrep-rules/xss.yaml \\
                          --json > semgrep-report.json
                    """
        
                    def reportText = readFile('semgrep-report.json')
                    def report = new groovy.json.JsonSlurper().parseText(reportText)
                    def findings = report.results.size()
        
                    if (findings > 0) {
                        echo "Semgrep: ${findings} güvenlik bulgusu tespit edildi!"
                        error("Semgrep bulguları mevcut.")
                    } else {
                        echo "Semgrep: Bulgu yok."
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
