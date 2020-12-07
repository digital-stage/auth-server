import * as dotenv from 'dotenv';
import * as fs from 'fs';
import debug from 'debug';

const report = debug('auth');

const resolveVariables = () => {
  if (process.env.ENV_PATH) {
    report(`Using custom environment file at ${process.env.ENV_PATH}`);
    const envConfig = dotenv.parse(fs.readFileSync(process.env.ENV_PATH));
    Object.keys(envConfig).forEach((k) => {
      process.env[k] = envConfig[k];
    });
  } else {
    dotenv.config();
  }
};
export default resolveVariables;
