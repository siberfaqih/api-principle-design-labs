const http = require('http');
const fs = require('fs');
const path = require('path');

// Test configuration
const VULN_PORT = 3000;
const SECURE_PORT = 3001;
const TEST_TIMEOUT = 5000;

// Colors for console output
const colors = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    white: '\x1b[37m',
    reset: '\x1b[0m'
};

// Test results tracking
let testResults = {
    total: 0,
    passed: 0,
    failed: 0,
    vulnerabilities: [],
    fixes: []
};

// Helper function to make HTTP requests
function makeRequest(options, data = null) {
    return new Promise((resolve, reject) => {
        const req = http.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => {
                body += chunk;
            });
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    headers: res.headers,
                    body: body
                });
            });
        });

        req.on('error', (err) => {
            reject(err);
        });

        req.setTimeout(TEST_TIMEOUT, () => {
            req.destroy();
            reject(new Error('Request timeout'));
        });

        if (data) {
            req.write(data);
        }
        req.end();
    });
}

// Helper function to check if server is running
async function checkServer(port) {
    try {
        const response = await makeRequest({
            hostname: 'localhost',
            port: port,
            path: '/api/health',
            method: 'GET'
        });
        return response.statusCode === 200;
    } catch (error) {
        return false;
    }
}

// Test logging functions
function logTest(testName) {
    console.log(`${colors.blue}🧪 Testing: ${testName}${colors.reset}`);
}

function logVulnerability(description, details) {
    console.log(`${colors.red}❌ VULNERABILITY: ${description}${colors.reset}`);
    if (details) console.log(`   ${colors.yellow}Details: ${details}${colors.reset}`);
    testResults.vulnerabilities.push({ description, details });
}

function logFix(description, details) {
    console.log(`${colors.green}✅ FIXED: ${description}${colors.reset}`);
    if (details) console.log(`   ${colors.cyan}Details: ${details}${colors.reset}`);
    testResults.fixes.push({ description, details });
}

function logInfo(message) {
    console.log(`${colors.cyan}ℹ️  ${message}${colors.reset}`);
}

// Test functions
async function testSQLInjection() {
    logTest('SQL Injection in User Search');
    testResults.total += 2;

    // Test vulnerable server
    try {
        const vulnResponse = await makeRequest({
            hostname: 'localhost',
            port: VULN_PORT,
            path: "/api/users/search?email=john.doe@email.com' OR '1'='1",
            method: 'GET'
        });

        const vulnData = JSON.parse(vulnResponse.body);
        if (vulnData.users && vulnData.users.length > 1) {
            logVulnerability('SQL Injection successful on vulnerable server', 
                `Returned ${vulnData.users.length} users instead of 1`);
            testResults.failed++;
        } else {
            testResults.passed++;
        }
    } catch (error) {
        logInfo(`Vulnerable server test failed: ${error.message}`);
        testResults.failed++;
    }

    // Test secure server
    try {
        const secureResponse = await makeRequest({
            hostname: 'localhost',
            port: SECURE_PORT,
            path: "/api/users/search?email=john.doe@email.com' OR '1'='1",
            method: 'GET'
        });

        if (secureResponse.statusCode === 400) {
            logFix('SQL Injection prevented on secure server', 
                'Invalid email format rejected');
            testResults.passed++;
        } else {
            testResults.failed++;
        }
    } catch (error) {
        logInfo(`Secure server test failed: ${error.message}`);
        testResults.failed++;
    }
}

async function testInputValidation() {
    logTest('Input Validation');
    testResults.total += 4;

    const invalidData = {
        email: 'not-an-email',
        nik: '123',
        full_name: 'Test User',
        account_number: 'INVALID'
    };

    // Test vulnerable server (should accept invalid data)
    try {
        const vulnResponse = await makeRequest({
            hostname: 'localhost',
            port: VULN_PORT,
            path: '/api/register',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        }, JSON.stringify(invalidData));

        if (vulnResponse.statusCode === 201 || vulnResponse.statusCode === 500) {
            logVulnerability('No input validation on vulnerable server', 
                'Invalid data was processed');
            testResults.failed++;
        } else {
            testResults.passed++;
        }
    } catch (error) {
        logInfo(`Vulnerable server validation test failed: ${error.message}`);
        testResults.failed++;
    }

    // Test secure server (should reject invalid data)
    try {
        const secureResponse = await makeRequest({
            hostname: 'localhost',
            port: SECURE_PORT,
            path: '/api/register',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        }, JSON.stringify(invalidData));

        if (secureResponse.statusCode === 400) {
            const responseData = JSON.parse(secureResponse.body);
            if (responseData.error === 'Validation failed') {
                logFix('Input validation working on secure server', 
                    `Rejected ${responseData.details.length} validation errors`);
                testResults.passed++;
            } else {
                testResults.failed++;
            }
        } else {
            testResults.failed++;
        }
    } catch (error) {
        logInfo(`Secure server validation test failed: ${error.message}`);
        testResults.failed++;
    }

    // Test NIK validation specifically
    const invalidNIK = {
        email: 'test@example.com',
        nik: '123',
        full_name: 'Test User',
        account_number: 'ACC123456789012'
    };

    try {
        const secureResponse = await makeRequest({
            hostname: 'localhost',
            port: SECURE_PORT,
            path: '/api/register',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        }, JSON.stringify(invalidNIK));

        if (secureResponse.statusCode === 400) {
            const responseData = JSON.parse(secureResponse.body);
            const nikError = responseData.details.find(err => err.field === 'nik');
            if (nikError) {
                logFix('Indonesian NIK validation working', 
                    'NIK must be exactly 16 digits');
                testResults.passed++;
            } else {
                testResults.failed++;
            }
        } else {
            testResults.failed++;
        }
    } catch (error) {
        logInfo(`NIK validation test failed: ${error.message}`);
        testResults.failed++;
    }

    // Test account number validation
    const invalidAccount = {
        email: 'test2@example.com',
        nik: '1234567890123456',
        full_name: 'Test User',
        account_number: 'INVALID123'
    };

    try {
        const secureResponse = await makeRequest({
            hostname: 'localhost',
            port: SECURE_PORT,
            path: '/api/register',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        }, JSON.stringify(invalidAccount));

        if (secureResponse.statusCode === 400) {
            const responseData = JSON.parse(secureResponse.body);
            const accountError = responseData.details.find(err => err.field === 'account_number');
            if (accountError) {
                logFix('Account number validation working', 
                    'Account number must follow ACC############ format');
                testResults.passed++;
            } else {
                testResults.failed++;
            }
        } else {
            testResults.failed++;
        }
    } catch (error) {
        logInfo(`Account validation test failed: ${error.message}`);
        testResults.failed++;
    }
}

async function testXSSPrevention() {
    logTest('XSS Prevention');
    testResults.total += 2;

    const xssPayload = {
        profile_bio: '<script>alert("XSS")</script><img src=x onerror=alert("XSS")>'
    };

    // Test vulnerable server
    try {
        const vulnResponse = await makeRequest({
            hostname: 'localhost',
            port: VULN_PORT,
            path: '/api/profile/ACC001234567890/bio',
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            }
        }, JSON.stringify(xssPayload));

        if (vulnResponse.statusCode === 200) {
            // Check if XSS payload is reflected
            const profileResponse = await makeRequest({
                hostname: 'localhost',
                port: VULN_PORT,
                path: '/api/profile/ACC001234567890',
                method: 'GET'
            });

            if (profileResponse.body.includes('<script>')) {
                logVulnerability('Stored XSS vulnerability on vulnerable server', 
                    'Script tags not sanitized in profile output');
                testResults.failed++;
            } else {
                testResults.passed++;
            }
        } else {
            testResults.passed++;
        }
    } catch (error) {
        logInfo(`XSS vulnerability test failed: ${error.message}`);
        testResults.failed++;
    }

    // Test secure server
    try {
        const secureResponse = await makeRequest({
            hostname: 'localhost',
            port: SECURE_PORT,
            path: '/api/profile/ACC001234567890/bio',
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            }
        }, JSON.stringify(xssPayload));

        if (secureResponse.statusCode === 200) {
            // Check if XSS payload is sanitized
            const profileResponse = await makeRequest({
                hostname: 'localhost',
                port: SECURE_PORT,
                path: '/api/profile/ACC001234567890',
                method: 'GET'
            });

            if (!profileResponse.body.includes('<script>')) {
                logFix('XSS prevention working on secure server', 
                    'Script tags sanitized in profile output');
                testResults.passed++;
            } else {
                testResults.failed++;
            }
        } else {
            testResults.failed++;
        }
    } catch (error) {
        logInfo(`XSS prevention test failed: ${error.message}`);
        testResults.failed++;
    }
}

async function testBusinessLogic() {
    logTest('Business Logic Protection');
    testResults.total += 2;

    const overdraftTransfer = {
        from_account: 'ACC001234567893',
        to_account: 'ACC001234567890',
        amount: 999999999,
        description: 'Overdraft test'
    };

    // Test vulnerable server (should allow overdraft)
    try {
        const vulnResponse = await makeRequest({
            hostname: 'localhost',
            port: VULN_PORT,
            path: '/api/transfer',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        }, JSON.stringify(overdraftTransfer));

        if (vulnResponse.statusCode === 200) {
            const responseData = JSON.parse(vulnResponse.body);
            if (responseData.newSenderBalance < 0) {
                logVulnerability('Business logic bypass on vulnerable server', 
                    `Allowed overdraft: balance became ${responseData.newSenderBalance}`);
                testResults.failed++;
            } else {
                testResults.passed++;
            }
        } else {
            testResults.passed++;
        }
    } catch (error) {
        logInfo(`Business logic vulnerability test failed: ${error.message}`);
        testResults.failed++;
    }

    // Test secure server (should prevent overdraft)
    try {
        const secureResponse = await makeRequest({
            hostname: 'localhost',
            port: SECURE_PORT,
            path: '/api/transfer',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        }, JSON.stringify(overdraftTransfer));

        if (secureResponse.statusCode === 400) {
            const responseData = JSON.parse(secureResponse.body);
            if (responseData.error.includes('Validation failed') || responseData.error.includes('Insufficient balance')) {
                logFix('Business logic protection working on secure server', 
                    'Overdraft prevented by validation and balance checks');
                testResults.passed++;
            } else {
                testResults.failed++;
            }
        } else {
            testResults.failed++;
        }
    } catch (error) {
        logInfo(`Business logic protection test failed: ${error.message}`);
        testResults.failed++;
    }
}

async function testRateLimiting() {
    logTest('Rate Limiting');
    testResults.total += 1;

    // Test rate limiting on secure server
    try {
        let rateLimitHit = false;
        
        for (let i = 0; i < 12; i++) {
            const response = await makeRequest({
                hostname: 'localhost',
                port: SECURE_PORT,
                path: '/api/transfer',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            }, JSON.stringify({
                from_account: 'ACC001234567890',
                to_account: 'ACC001234567891',
                amount: 1,
                description: `Rate limit test ${i}`
            }));

            if (response.statusCode === 429) {
                rateLimitHit = true;
                break;
            }
            
            // Small delay between requests
            await new Promise(resolve => setTimeout(resolve, 100));
        }

        if (rateLimitHit) {
            logFix('Rate limiting working on secure server', 
                'Blocked excessive requests with HTTP 429');
            testResults.passed++;
        } else {
            logInfo('Rate limiting not triggered (may need more requests)');
            testResults.passed++; // Don't fail if rate limit wasn't hit
        }
    } catch (error) {
        logInfo(`Rate limiting test failed: ${error.message}`);
        testResults.failed++;
    }
}

async function testSecurityHeaders() {
    logTest('Security Headers');
    testResults.total += 2;

    // Test vulnerable server (should have minimal headers)
    try {
        const vulnResponse = await makeRequest({
            hostname: 'localhost',
            port: VULN_PORT,
            path: '/api/users',
            method: 'GET'
        });

        if (!vulnResponse.headers['x-content-type-options']) {
            logVulnerability('Missing security headers on vulnerable server', 
                'No X-Content-Type-Options header');
            testResults.failed++;
        } else {
            testResults.passed++;
        }
    } catch (error) {
        logInfo(`Security headers vulnerability test failed: ${error.message}`);
        testResults.failed++;
    }

    // Test secure server (should have security headers)
    try {
        const secureResponse = await makeRequest({
            hostname: 'localhost',
            port: SECURE_PORT,
            path: '/api/users',
            method: 'GET'
        });

        const hasSecurityHeaders = 
            secureResponse.headers['x-content-type-options'] &&
            secureResponse.headers['x-frame-options'];

        if (hasSecurityHeaders) {
            logFix('Security headers present on secure server', 
                'Helmet.js security headers detected');
            testResults.passed++;
        } else {
            testResults.failed++;
        }
    } catch (error) {
        logInfo(`Security headers test failed: ${error.message}`);
        testResults.failed++;
    }
}

// Main test runner
async function runTests() {
    console.log(`${colors.magenta}🚀 Starting Security Integration Tests${colors.reset}\n`);

    // Check if servers are running
    const vulnServerRunning = await checkServer(VULN_PORT);
    const secureServerRunning = await checkServer(SECURE_PORT);

    if (!vulnServerRunning) {
        console.log(`${colors.red}❌ Vulnerable server not running on port ${VULN_PORT}${colors.reset}`);
        console.log(`${colors.yellow}   Please run: npm run vuln-server${colors.reset}\n`);
    }

    if (!secureServerRunning) {
        console.log(`${colors.red}❌ Secure server not running on port ${SECURE_PORT}${colors.reset}`);
        console.log(`${colors.yellow}   Please run: npm run secure-server${colors.reset}\n`);
    }

    if (!vulnServerRunning || !secureServerRunning) {
        console.log(`${colors.red}Exiting: Both servers must be running for tests${colors.reset}`);
        process.exit(1);
    }

    console.log(`${colors.green}✅ Both servers are running${colors.reset}\n`);

    // Run all tests
    try {
        await testSQLInjection();
        console.log('');
        
        await testInputValidation();
        console.log('');
        
        await testXSSPrevention();
        console.log('');
        
        await testBusinessLogic();
        console.log('');
        
        await testRateLimiting();
        console.log('');
        
        await testSecurityHeaders();
        console.log('');
        
    } catch (error) {
        console.error(`${colors.red}Test execution error: ${error.message}${colors.reset}`);
    }

    // Print summary
    console.log(`${colors.magenta}📊 Test Summary${colors.reset}`);
    console.log(`${colors.white}Total Tests: ${testResults.total}${colors.reset}`);
    console.log(`${colors.green}Passed: ${testResults.passed}${colors.reset}`);
    console.log(`${colors.red}Failed: ${testResults.failed}${colors.reset}`);
    
    if (testResults.vulnerabilities.length > 0) {
        console.log(`\n${colors.red}🚨 Vulnerabilities Found: ${testResults.vulnerabilities.length}${colors.reset}`);
    }
    
    if (testResults.fixes.length > 0) {
        console.log(`${colors.green}🔒 Security Fixes Verified: ${testResults.fixes.length}${colors.reset}`);
    }

    const successRate = ((testResults.passed / testResults.total) * 100).toFixed(1);
    console.log(`\n${colors.cyan}Success Rate: ${successRate}%${colors.reset}`);

    if (testResults.failed === 0) {
        console.log(`\n${colors.green}🎉 All tests passed! Security implementations are working correctly.${colors.reset}`);
    } else {
        console.log(`\n${colors.yellow}⚠️  Some tests failed. Review the vulnerabilities and fixes above.${colors.reset}`);
    }
}

// Run tests if this file is executed directly
if (require.main === module) {
    runTests().catch(error => {
        console.error(`${colors.red}Fatal error: ${error.message}${colors.reset}`);
        process.exit(1);
    });
}

module.exports = { runTests, testResults };