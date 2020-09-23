module.exports = {
    apps: [{
        name: "auth-server",
        script: "dist/index.js",

        // Options reference: https://pm2.keymetrics.io/docs/usage/application-declaration/
        instances: 1,
        autorestart: true,
        watch: false,
        max_memory_restart: '1G',
        env: {
            NODE_ENV: 'development'
        },
        env_production: {
            "NODE_ENV": "production",
            "ENV_PATH": "/home/node/.env",
        }
    }],

    deploy: {
        production: {
            user: 'node',
            host: 'auth.api.digital-stage.org',
            ref: 'origin/master',
            repo: "https://github.com/digital-stage/auth-server.git",
            path: '/node/auth-server',
            env: {
                "NODE_ENV": "production",
                "ENV_PATH": "/home/node/.env",
            },
            'post-deploy': 'npm install && npm run build && pm2 reload ecosystem.config.js --env production'
        }
    }
};
