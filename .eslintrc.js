module.exports = {
    extends: [
        'airbnb-typescript/base',
        "plugin:promise/recommended",
        "plugin:prettier/recommended"
    ],
    plugins: ["import"],
    rules: {
        "no-underscore-dangle": 0,
        "promise/no-nesting": 0,
        "prettier/prettier": [
            "error",
            {
                "endOfLine": "auto"
            },
        ],
    },
    parserOptions: {
        project: './tsconfig.json'
    }
};
