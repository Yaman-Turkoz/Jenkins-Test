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

    // ─────────────────────────────────────────────────────────────────────────
    // Environment Variables
    //
    // BUILD_NUMBER is appended to network and container names so that
    // multiple concurrent pipeline runs never collide.
    //
    // Required Jenkins credentials:
    //   - "groq-api-key"  : Secret text  → Groq API key
    //   - "github-token"  : Secret text  → GitHub PAT with repo + issues scope
    //
    // HOST_JENKINS_HOME is only needed for ZAP (volume mount into container).
    // Semgrep runs directly inside Jenkins — no Docker, no volume needed.
    // ─────────────────────────────────────────────────────────────────────────
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

        // ─────────────────────────────────────────────────────────────────────
        stage('Clean Workspace') {
            steps { deleteDir() }
        }

        // ─────────────────────────────────────────────────────────────────────
        stage('Checkout') {
            steps { checkout scm }
        }

        // ─────────────────────────────────────────────────────────────────────
        // SAST — Semgrep runs directly inside Jenkins (pip install semgrep
        // was done in the Dockerfile). No Docker socket needed here.
        // --baseline-commit HEAD~1 → only findings introduced by this commit.
        // ─────────────────────────────────────────────────────────────────────
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

        // ─────────────────────────────────────────────────────────────────────
        // DAST Stage 1: Start and prepare DVWA
        //
        // Steps:
        //   1. Create a build-specific Docker network
        //   2. Start the DVWA container on that network
        //   3. Wait until DVWA responds with HTTP 200/302 (max ~2 minutes)
        //   4. Set default_security_level to "low" in the DVWA PHP config
        //   5. Initialize the DB and log in via curl to confirm everything works
        //   6. (Debug) Verify the XSS page is reachable while authenticated
        // ─────────────────────────────────────────────────────────────────────
        stage('DAST: Start DVWA') {
            steps {
                script {

                    // 1. Create the Docker network
                    sh "docker network create ${NET_NAME}"

                    // 2. Start DVWA
                    sh """
                        docker run -d \\
                            --name ${DVWA_NAME} \\
                            --network ${NET_NAME} \\
                            vulnerables/web-dvwa
                    """

                    // 3. Wait until DVWA is ready
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

                    // 4. Set security level to "low" in the PHP config file
                    sh """docker exec ${DVWA_NAME} sed -i "s/default_security_level' ] = '[^']*'/default_security_level' ] = 'low'/" /var/www/html/config/config.inc.php 2>/dev/null || true"""

                    // 5. DB init + login + set security level via curl
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

        // ─────────────────────────────────────────────────────────────────────
        // DAST Stage 2: ZAP XSS scan
        //
        // Key fixes vs previous version:
        //
        //   Authentication:
        //     DVWA uses a CSRF token (user_token) on the login form.
        //     ZAP's built-in form auth handles CSRF tokens automatically
        //     when the token name is listed under antiCsrfTokenNames.
        //     We keep the form auth approach but move antiCsrfTokenNames
        //     under the context (not under env.parameters where ZAP ignores it).
        //
        //   Spider:
        //     Added ajaxSpider after the traditional spider to discover
        //     JavaScript-rendered links inside the authenticated DVWA session.
        //     The traditional spider alone misses most /vulnerabilities/ pages.
        //
        //   Active Scan policy:
        //     "defaultStrength: disabled" is not a valid ZAP value and was
        //     silently ignored.  The correct way to suppress all other rules
        //     is "defaultThreshold: off" — this disables every rule that is
        //     not explicitly listed below.  The four XSS rules are given
        //     explicit strength/threshold values so they run normally.
        // ─────────────────────────────────────────────────────────────────────
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

        // ─────────────────────────────────────────────────────────────────────
        // DAST Stage 3: AI validation and GitHub Issue
        //
        // scripts/zap_analyze.py:
        //   1. Extracts XSS findings (rule IDs 40012/40014/40016/40017) from
        //      zap-report.json
        //   2. Asks Groq LLM for each finding: true or false positive?
        //   3. Writes all true positives with their PoCs into a single GitHub Issue
        //   4. Saves full results to zap-analysis.json
        //
        // --network host → Python container needs internet for Groq + GitHub APIs.
        // BUILD_NUMBER is passed so the GitHub Issue title includes the build no.
        // ─────────────────────────────────────────────────────────────────────
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

    // ─────────────────────────────────────────────────────────────────────────
    // Post Actions — runs on every outcome (success, failure, abort)
    // ─────────────────────────────────────────────────────────────────────────
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
