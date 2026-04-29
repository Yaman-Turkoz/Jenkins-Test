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
        stage('ZAP AI Analysis') {
            steps {
                script {
                    def gitUrl   = env.GIT_URL ?: scm.getUserRemoteConfigs()[0].getUrl()
                    def repoName = gitUrl
                        .replaceFirst(/^.*github\.com[\/:]/, '')
                        .replaceFirst(/\.git$/, '')
        
                    withCredentials([
                        string(credentialsId: 'GITHUB_TOKEN', variable: 'GH_TOKEN'),
                        string(credentialsId: 'GROQ_API_KEY', variable: 'GROQ_API_KEY'),
                    ]) {
                        sh """
                            REPO=${repoName} \
                            GH_TOKEN=${GH_TOKEN} \
                            python3 ${WORKSPACE}/scripts/zap_create_issues.py
        
                            REPO=${repoName} \
                            GH_TOKEN=${GH_TOKEN} \
                            GROQ_API_KEY=${GROQ_API_KEY} \
                            python3 ${WORKSPACE}/scripts/zap_ai_analyze.py
                        """
                    }
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'zap-created-issues.json',
                                     allowEmptyArchive: true
                }
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'semgrep-report.json,zap/dvwa-xss-report-json.json',
                             allowEmptyArchive: true
        }
    }
}
