const path = require('path');
const CopyPlugin = require('copy-webpack-plugin');

module.exports = {
  entry: {
    background: './background.js',
    popup: './popup.js'
  },
  output: {
    path: path.resolve(__dirname, 'dist'),
    filename: '[name].js'
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /node_modules/,
        use: {
          loader: 'babel-loader',
          options: {
            presets: ['@babel/preset-env']
          }
        }
      }
    ]
  },
  plugins: [
    new CopyPlugin({
      patterns: [
        { from: 'manifest.json', to: 'manifest.json' },
        { from: 'popup.html', to: 'popup.html' },
        { from: 'styles.css', to: 'styles.css' },
        { from: 'icons', to: 'icons' }
      ]
    })
  ],
  resolve: {
    fallback: {
      "stream": require.resolve("stream-browserify"),
      "buffer": require.resolve("buffer/"),
      "path": require.resolve("path-browserify"),
      "util": require.resolve("util/")
    }
  },
  performance: {
    hints: false,
    maxEntrypointSize: 512000,
    maxAssetSize: 512000
  }
};