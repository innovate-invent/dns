// Karma configuration
// Generated on Sun Dec 25 2022 16:10:46 GMT-0800 (Pacific Standard Time)

module.exports = (config) => {
  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    // basePath: '/base',


    // frameworks to use
    // available frameworks: https://www.npmjs.com/search?q=keywords:karma-adapter
    frameworks: ['mocha', 'karma-typescript'],


    // list of files / patterns to load in the browser
    files: [
      {pattern: 'node_modules/chai/*.js', included: false, watched: false},
      {pattern: 'node_modules/chai-as-promised/lib/*.js', included: false, watched: false},
      {pattern: 'node_modules/check-error/*.js', included: false, watched: false},
      {pattern: 'spec/importmap.js', type: 'js'},
      {pattern: 'spec/*.ts', type: 'module'},
      {pattern: 'src/*.ts', type: 'module', included: false},
    ],


    // list of files / patterns to exclude
    exclude: [
        'spec/nodejs.spec.ts',
        'spec/rfc7766.spec.ts',
        'src/rfc7766.ts'
    ],


    // preprocess matching files before serving them to the browser
    // available preprocessors: https://www.npmjs.com/search?q=keywords:karma-preprocessor
    preprocessors: {
      'spec/*.ts': ['karma-typescript'],
      'src/*.ts': ['karma-typescript', 'coverage'],
    },

    karmaTypescriptConfig: {
      "compilerOptions": {
        "target": "ES2023",
        "module": "ES2023",
        "paths": { // This is solely to stop a bug with @types/node as of 12/15/2023
          "undici-types": [
            "./node_modules/undici-types/index.d.ts"
          ]
        }
      }
    },

    // test results reporter to use
    // possible values: 'dots', 'progress'
    // available reporters: https://www.npmjs.com/search?q=keywords:karma-reporter
    reporters: ['progress', 'coverage', 'karma-typescript'],


    // web server port
    port: 9876,


    // enable / disable colors in the output (reporters and logs)
    colors: true,


    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,


    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: true,


    // start these browsers
    // available browser launchers: https://www.npmjs.com/search?q=keywords:karma-launcher
    browsers: ['ChromiumHeadless'],


    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: false,

    // Concurrency level
    // how many browser instances should be started simultaneously
    concurrency: Infinity,
  })
}
