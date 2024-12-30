const errors = require('../helpers/helpers')

const errorMiddleware = (err, req, res, next) => {
    console.error(err, 'Error desde el middleware')
    const errorDetails = errors[err.message] || errors['SERVER_ERROR']

    const response = {
        id: errorDetails.id,
        message: errorDetails.message,
        description: errorDetails.description
    }

    res.status(errorDetails.statusCode).json(response)
}

module.exports = errorMiddleware