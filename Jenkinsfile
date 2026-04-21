@NonCPS
int countSemgrepFindings(String reportText) {
    def report = new groovy.json.JsonSlurper().parseText(reportText)
    return report.results.size()
}

@NonCPS
int countZapAlerts(String reportText) {
    def report = new groovy.json.JsonSlurper().parseText(reportText)
    return report.site?.collectMany { it.alerts ?: [] }?.size() ?: 0
}



pipeline {
    agent any

    environment {
        NET_NAME     = "devsecops-net-${BUILD_NUMBER}"
        DVWA_NAME    = "dvwa-${BUILD_NUMBER}"
        GROQ_API_KEY = credentials('groq-api-key')
        GITHUB_TOKEN = credentials('github-token')
        GITHUB_REPO  = 'Yaman-Turkoz/Jenkins-Test'
    }

    options {
        skipDefaultCheckout(true)
    }

    stages {

        stage('Clean Workspace') {
            steps { deleteDir() }
        }


        stage('Checkout') {
            steps { checkout scm }
        }


        stage('Semgrep Scan') {
            steps {
                script {
                    sh """
                        semgrep scan . \\
                            --config=semgrep-rules/pipeline-rules.yaml \\
                            --baseline-commit HEAD~1 \\
                            --json \\
                            --output=semgrep-report.json || true
                    """

                    def reportText = readFile('semgrep-report.json').trim()
                    if (!reportText) error("Semgrep report is empty — scan may have failed.")

                    def findings = countSemgrepFindings(reportText)

                    if (findings > 0) {
                        echo "Semgrep: ${findings} critical finding(s) detected."
                        error("Semgrep: Pipeline failed due to critical findings.")
                    } else {
                        echo "Semgrep: No findings."
                    }
                }
            }
        }


        stage('DAST: Start DVWA') {
            steps {
                script {

                    sh "docker network create ${NET_NAME}"


                    sh """
                        docker run -d \\
                            --name ${DVWA_NAME} \\
                            --network ${NET_NAME} \\
                            vulnerables/web-dvwa
                    """


                    sh """
                        docker run --rm \\
                            --network ${NET_NAME} \\
                            curlimages/curl:latest \\
                            sh -c '
                                echo "=== Waiting for DVWA... ==="
                                for i in \$(seq 1 40); do
                                    STATUS=\$(curl -so /dev/null -w "%{http_code}" \\
                                        http://${DVWA_NAME}/ 2>/dev/null || echo "000")
                                    if [ "\$STATUS" = "200" ] || [ "\$STATUS" = "302" ]; then
                                        echo "DVWA is ready! (attempt \$i, HTTP \$STATUS)"
                                        exit 0
                                    fi
                                    echo "Attempt \$i: HTTP \$STATUS — waiting 3s..."
                                    sleep 3
                                done
                                echo "ERROR: DVWA did not start within 120 seconds!" >&2
                                exit 1
                            '
                    """

                    sh """docker exec ${DVWA_NAME} sed -i "s/default_security_level' ] = '[^']*'/default_security_level' ] = 'low'/" /var/www/html/config/config.inc.php 2>/dev/null || true"""


                    sh """
                        docker run --rm \\
                            --network ${NET_NAME} \\
                            curlimages/curl:latest \\
                            sh -c '
                                echo "--- DB init ---"
                                curl -sf -c /tmp/jar.txt \\
                                    http://${DVWA_NAME}/setup.php -o /dev/null
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    -X POST http://${DVWA_NAME}/setup.php \\
                                    -d "create_db=Create+%2F+Reset+Database" \\
                                    -o /dev/null
                                echo "DB init done."

                                echo "--- Login ---"
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    http://${DVWA_NAME}/login.php -o /dev/null
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    -X POST http://${DVWA_NAME}/login.php \\
                                    -d "username=admin&password=password&Login=Login" \\
                                    -L -o /dev/null
                                echo "Login done."

                                echo "--- Security = low ---"
                                curl -sf -b /tmp/jar.txt -c /tmp/jar.txt \\
                                    -X POST http://${DVWA_NAME}/security.php \\
                                    -d "seclev_submit=Submit&security=low" \\
                                    -L -o /dev/null
                                echo "Security level set to low."

                                echo "--- Auth check: XSS page ---"
                                STATUS=\$(curl -so /dev/null -w "%{http_code}" \\
                                    -b /tmp/jar.txt \\
                                    http://${DVWA_NAME}/vulnerabilities/xss_r/)
                                echo "XSS reflected page HTTP status: \$STATUS"
                                if [ "\$STATUS" != "200" ]; then
                                    echo "WARNING: XSS page returned \$STATUS — auth may have failed!"
                                fi
                            '
                    """

                    echo "DVWA is ready and configured."
                }
            }
        }

    
        stage('DAST: ZAP XSS Scan') {
            steps {
                script {
                    def hostWorkspace = env.WORKSPACE.replace(
                        '/var/jenkins_home',
                        env.HOST_JENKINS_HOME
                    )

                    writeFile file: 'zap-automation.yaml', text: """---
env:
  contexts:
  - name: dvwa
    urls:
    - "http://${DVWA_NAME}/"
    includePaths:
    - "http://${DVWA_NAME}/.*"
    excludePaths:
    - "http://${DVWA_NAME}/logout.php"
    - "http://${DVWA_NAME}/setup.php"
    authentication:
      method: form
      parameters:
        loginPageUrl: "http://${DVWA_NAME}/login.php"
        loginRequestData: "username={%username%}&password={%password%}&Login=Login&user_token={%user_token%}"
      verification:
        method: response
        loggedInRegex: "(?i)(logout|DVWA Security|Welcome)"
        loggedOutRegex: "(?i)(login\\.php|Login Required)"
    sessionManagement:
      method: cookie
    users:
    - name: admin
      credentials:
        username: "admin"
        password: "password"
    technology: {}
    # CSRF token name — must be declared at context level so ZAP
    # extracts it from the login page before submitting the form.
    antiCsrfTokenNames:
    - user_token
  parameters:
    failOnError: false
    failOnWarning: false
    progressToStdout: true

jobs:
# ── Traditional spider (fast, link-based) ──────────────────────────────────
- type: spider
  parameters:
    context: dvwa
    user: admin
    url: "http://${DVWA_NAME}/"
    maxDuration: 3
    maxChildren: 50
    acceptCookies: true

# ── Ajax spider (JS-rendered pages / dynamic navigation) ───────────────────
# Discovers /vulnerabilities/* pages that the traditional spider misses
# because they are linked from a JavaScript-driven side menu.
- type: ajaxSpider
  parameters:
    context: dvwa
    user: admin
    url: "http://${DVWA_NAME}/"
    maxDuration: 3

# ── Active Scan — XSS rules only ───────────────────────────────────────────
# defaultThreshold: off   → disables EVERY rule not listed below.
# Only the four XSS rule IDs are given explicit thresholds, so only
# those four will fire.  This replaces the invalid "disabled" strength
# that was silently ignored in the previous configuration.
- type: activeScan
  parameters:
    context: dvwa
    user: admin
    maxRuleDurationInMins: 10
    maxScanDurationInMins: 20
  policyDefinition:
    defaultStrength: medium
    defaultThreshold: off
    rules:
    - id: 40012
      name: "Cross Site Scripting (Reflected)"
      strength: high
      threshold: medium
    - id: 40014
      name: "Cross Site Scripting (Persistent)"
      strength: high
      threshold: medium
    - id: 40016
      name: "Cross Site Scripting (Persistent) - Prime"
      strength: high
      threshold: medium
    - id: 40017
      name: "Cross Site Scripting (Persistent) - Spider"
      strength: high
      threshold: medium

- type: report
  parameters:
    template: traditional-json
    reportDir: "/zap/wrk"
    reportFile: "zap-report"
    reportTitle: "ZAP XSS Scan - DVWA"
    reportDescription: "Jenkins DAST Pipeline - Build ${BUILD_NUMBER}"
"""

                    sh """
                        docker run --rm \\
                            --network ${NET_NAME} \\
                            -v ${hostWorkspace}:/zap/wrk/:rw \\
                            ghcr.io/zaproxy/zaproxy:stable \\
                            zap.sh -cmd -autorun /zap/wrk/zap-automation.yaml \\
                        || true
                    """

                    if (!fileExists('zap-report.json')) {
                        echo "WARNING: zap-report.json not found. Creating empty report."
                        writeFile file: 'zap-report.json', text: '{"site":[]}'
                    }

                    def totalAlerts = countZapAlerts(readFile('zap-report.json'))
                    echo "ZAP scan complete — ${totalAlerts} alert(s) found."
                }
            }
        }

        stage('DAST: AI Analysis & GitHub Issue') {
            steps {
                script {
                    def hostWorkspace = env.WORKSPACE.replace(
                        '/var/jenkins_home',
                        env.HOST_JENKINS_HOME
                    )

                    sh """
                        docker run --rm \\
                            --network host \\
                            -v ${hostWorkspace}:/workspace \\
                            -e GROQ_API_KEY=${GROQ_API_KEY} \\
                            -e GITHUB_TOKEN=${GITHUB_TOKEN} \\
                            -e GITHUB_REPO=${GITHUB_REPO} \\
                            -e BUILD_NUMBER=${BUILD_NUMBER} \\
                            python:3.11-slim \\
                            sh -c '
                                pip install requests --quiet --no-cache-dir
                                python3 /workspace/scripts/zap_analyze.py \\
                                    --report /workspace/zap-report.json \\
                                    --output /workspace/zap-analysis.json
                            '
                    """
                }
            }
        }
    }

    post {
        always {
            sh """
                echo "=== Cleanup ==="
                docker stop ${DVWA_NAME} 2>/dev/null || true
                docker rm   ${DVWA_NAME} 2>/dev/null || true
                docker network rm ${NET_NAME} 2>/dev/null || true
                echo "DVWA container and network removed."
            """
            archiveArtifacts(
                artifacts: 'semgrep-report.json,zap-report.json,zap-automation.yaml,zap-analysis.json',
                allowEmptyArchive: true
            )
        }
    }
}
