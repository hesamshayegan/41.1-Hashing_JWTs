/** Middleware for handling req authorization for routes. */

const jwt = require("jsonwebtoken");
const { SECRET_KEY } = require("../config");

/** Middleware: Authenticate user. */

// authenticateJWT: This middleware function is responsible for authenticating a user by verifying a JSON Web Token (JWT) included 
// in the request body. It uses the jsonwebtoken library to verify the token using a secret key (SECRET_KEY). If the verification 
// is successful, it extracts the payload from the token and assigns it to req.user, creating a current user. The function then calls
// the next function to proceed to the next middleware or route handler. If the token verification fails, the function also calls
// next to continue processing the request.

function authenticateJWT(req, res, next) {
  try {
    const tokenFromBody = req.body._token;
    const payload = jwt.verify(tokenFromBody, SECRET_KEY);
    req.user = payload; // create a current user
    return next();
  } catch (err) {
    return next();
  }
}

/** Middleware: Requires user is authenticated. */

// ensureLoggedIn: This middleware function checks if a user is authenticated by verifying if req.user exists.
// If req.user is not present, it means the user is not logged in, so the function calls next with an error object containing
// a status code of 401 (Unauthorized) and a message indicating the user is unauthorized. If req.user exists, the function 
// calls next to continue processing the request.

function ensureLoggedIn(req, res, next) {
  if (!req.user) {
    return next({ status: 401, message: "Unauthorized" });
  } else {
    return next();
  }
}

/** Middleware: Requires correct username. */

// ensureCorrectUser: This middleware function ensures that the request is being made by the correct user.
// It compares the username stored in req.user with the username specified in the request's URL parameters
// (req.params.username). If the usernames match, the function calls next to continue processing the request.
// If the usernames don't match, the function calls next with an error object indicating unauthorized access.

function ensureCorrectUser(req, res, next) {
  try {
    if (req.user.username === req.params.username) {
      return next();
    } else {
      return next({ status: 401, message: "Unauthorized" });
    }
  } catch (err) {
    // errors would happen here if we made a request and req.user is undefined
    return next({ status: 401, message: "Unauthorized" });
  }
}
// end

module.exports = {
  authenticateJWT,
  ensureLoggedIn,
  ensureCorrectUser
};
