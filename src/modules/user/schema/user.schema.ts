import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Document } from 'mongoose';

/**
 * Represents a user in the system.
 */
@Schema({
  toJSON: {
    virtuals: true,
    /**
     * Transforms the document before converting it to JSON.
     * Removes the "_id" and "__v" fields from the JSON representation.
     * @param doc - The document being transformed.
     * @param ret - The transformed JSON representation of the document.
     * @returns The transformed JSON representation of the document.
     */
    transform: function (doc: any, ret: any) {
      delete ret._id;
      delete ret.__v;
      return ret;
    },
  },
  timestamps: true,
})
export class Users extends Document {
  /**
   * The username of the user.
   */
  @Prop({
    type: 'string',
    required: true,
  })
  username: string;

  /**
   * The email address of the user.
   */
  @Prop({
    type: 'string',
    required: true,
  })
  email: string;

  /**
   * The password of the user.
   * Defaults to an empty string if not provided.
   */
  @Prop({
    type: 'string',
    required: false,
    default: '',
  })
  password: string;

  /**
   * The avatar URL of the user.
   */
  @Prop({
    type: String,
    required: true,
  })
  avatar: string;
}

/**
 * Represents a hydrated user document.
 */
export type UsersDocument = HydratedDocument<Users>;

/**
 * The Mongoose schema for the Users collection.
 */
export const UsersSchema = SchemaFactory.createForClass(Users);
