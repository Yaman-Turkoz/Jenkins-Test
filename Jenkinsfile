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
                    sh """
                        semgrep scan . \
                            --config=semgrep-rules/pipeline-rules.yaml \
                            --baseline-commit HEAD~1 \
                            --json \
                            --output=semgrep-report.json || true
                    """
                    def reportText = readFile('semgrep-report.json').trim()
                    if (!reportText) {
                        error("Semgrep report is empty. Scan may have failed.")
                    }
                    def report   = new groovy.json.JsonSlurper().parseText(reportText)
                    def findings = report.results.size()
                    if (findings > 0) {
                        echo "Semgrep: ${findings} critical finding(s) detected."
                        error("Semgrep: Pipeline failed due to critical findings.")
                    } else {
                        echo "Semgrep: No findings."
                    }
                }
            }
        }
        stage('ZAP Scan') {
            steps {
                sh '''
                    export ZAP_HOST_DIR=${HOST_JENKINS_HOME}/workspace/${JOB_NAME}/zap
                    docker-compose -f ${WORKSPACE}/docker-compose.yml \
                        --project-directory ${WORKSPACE} \
                        run --rm zap
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap/dvwa-xss-report.html',
                                     allowEmptyArchive: true
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
