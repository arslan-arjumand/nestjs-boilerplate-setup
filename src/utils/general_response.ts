import { Response } from "express"

/**
 * Sends a general response with the specified status, message, and data.
 *
 * @param {Object} options - The options for the general response.
 * @param {Object} options.response - The response object.
 * @param {string} options.message - The message to be sent in the response.
 * @param {number} options.status - The status code of the response.
 * @param {any} [options.data=null] - The optional data to be sent in the response.
 * @returns {Object} The response object.
 */
export const generalResponse = ({
  response,
  message,
  status,
  data = null
}: {
  response: Response
  message: string
  status: number
  data?: any
}): object =>
  response.status(status).json({
    status,
    message,
    data
  })
