import * as bcrypt from "bcrypt"

/**
 * Generates a hash value for the given string value.
 * @param value - The string value to be hashed.
 * @returns A Promise that resolves to the generated hash value.
 */
export const getHashValue = async (value: string): Promise<string> => {
  const result = await bcrypt.hash(value, 12)
  return result
}

/**
 * Compares a string value with a hash value.
 * @param value - The string value to be compared.
 * @param hashValue - The hash value to compare against.
 * @returns A Promise that resolves to a boolean indicating whether the values match.
 */
export const compareHashValue = async (value: string, hashValue: string): Promise<boolean> => {
  return bcrypt.compare(value, hashValue)
}
