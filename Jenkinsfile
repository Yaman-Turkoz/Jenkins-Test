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
                    def changedFiles = sh(
                        script: "git diff --name-only HEAD~1 HEAD -- '*.php' | tr '\\n' ' '",
                        returnStdout: true
                    ).trim()

                    if (!changedFiles) {
                        echo "No PHP files changed. Skipping scan."
                        return
                    }

                    echo "Scanning changed files: ${changedFiles}"

                    sh """
                        semgrep scan ${changedFiles} \
                            --config=semgrep-rules/pipeline-rules.yaml \
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
    }

    post {
        always {
            archiveArtifacts artifacts: 'semgrep-report.json', allowEmptyArchive: true
        }
    }
}
