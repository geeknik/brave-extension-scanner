/**
 * Acorn Walk - AST walker for acorn
 * This is a simplified version for use in browser extensions
 */

// Simple recursive AST walker
function recursive(node, visitors, base, state, override) {
  if (!node) return;
  
  const type = override || node.type;
  const found = visitors[type];
  
  if (found) found(node, state);
  
  if (base[type]) {
    base[type](node, state, recursive.bind(null, null, visitors, base));
  } else if (base.default) {
    base.default(node, state, recursive.bind(null, null, visitors, base));
  }
}

// Base walkers for different node types
const base = {};

// Program node
base.Program = (node, state, callback) => {
  if (node && node.body && Array.isArray(node.body)) {
    for (let i = 0; i < node.body.length; i++) {
      const bodyNode = node.body[i];
      if (bodyNode) callback(bodyNode, state);
    }
  }
};

// Function declaration
base.FunctionDeclaration = (node, state, callback) => {
  if (node.id) callback(node.id, state);
  
  for (let i = 0; i < node.params.length; i++) {
    callback(node.params[i], state);
  }
  
  callback(node.body, state);
};

// Variable declaration
base.VariableDeclaration = (node, state, callback) => {
  for (let i = 0; i < node.declarations.length; i++) {
    callback(node.declarations[i], state);
  }
};

// Variable declarator
base.VariableDeclarator = (node, state, callback) => {
  callback(node.id, state);
  if (node.init) callback(node.init, state);
};

// Expressions
base.ExpressionStatement = (node, state, callback) => {
  callback(node.expression, state);
};

// Call expression
base.CallExpression = (node, state, callback) => {
  if (node.callee) callback(node.callee, state);
  
  if (node.arguments && Array.isArray(node.arguments)) {
    for (let i = 0; i < node.arguments.length; i++) {
      if (node.arguments[i]) callback(node.arguments[i], state);
    }
  }
};

// Member expression
base.MemberExpression = (node, state, callback) => {
  callback(node.object, state);
  callback(node.property, state);
};

// Identifier
base.Identifier = () => {};

// Literal
base.Literal = () => {};

// New expression
base.NewExpression = (node, state, callback) => {
  callback(node.callee, state);
  
  for (let i = 0; i < node.arguments.length; i++) {
    callback(node.arguments[i], state);
  }
};

// Assignment expression
base.AssignmentExpression = (node, state, callback) => {
  callback(node.left, state);
  callback(node.right, state);
};

// Block statement
base.BlockStatement = (node, state, callback) => {
  for (let i = 0; i < node.body.length; i++) {
    callback(node.body[i], state);
  }
};

// Default for any other node types
base.default = () => {};

// Simple ancestor tracking
function ancestorWalk(node, visitors, base, state) {
  const ancestors = [];
  
  function process(node, state) {
    ancestors.push(node);
    recursive(node, visitors, base, state);
    ancestors.pop();
  }
  
  process(node, state);
}

// Walker functions for global access
function simple(node, visitors, baseWalkers, state) {
  return recursive(node, visitors, baseWalkers || base, state);
}

function ancestor(node, visitors, baseWalkers, state) {
  return ancestorWalk(node, visitors, baseWalkers || base, state);
}

// Export for ES6 modules
export { simple, ancestor, base };

// Default export
export default {
  simple,
  ancestor,
  base
};

// Make walk available globally for importScripts
if (typeof window !== 'undefined') {
  window.walk = {
    simple,
    ancestor,
    base
  };
} else if (typeof self !== 'undefined') {
  self.walk = {
    simple,
    ancestor,
    base
  };
}