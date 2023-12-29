import * as bcrypt from 'bcrypt';

export const getHashValue = async (value: string) => {
  const result = await bcrypt.hash(value, await bcrypt.genSalt(10));
  return result;
};

export const compareHashValue = async (value: string, hashValue: string) => {
  return bcrypt.compare(value, hashValue);
};
