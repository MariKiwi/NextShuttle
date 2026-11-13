import {defineConfig,devices} from '@playwright/test';
export default defineConfig({testDir:'tests/browser',workers:1,fullyParallel:false,timeout:60000,
 use:{baseURL:'http://127.0.0.1:9084',trace:'retain-on-failure'},
 projects:[{name:'desktop',use:{...devices['Desktop Chrome']}},{name:'mobile',use:{...devices['Pixel 5']}}],
 webServer:{command:'PYTHONPATH=. python3 tests/browser_server.py',url:'http://127.0.0.1:9084/nextshuttle/',timeout:15000,reuseExistingServer:false}});
