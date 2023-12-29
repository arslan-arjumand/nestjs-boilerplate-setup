import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Document, Schema as MongooseSchema } from 'mongoose';

@Schema({
  toJSON: {
    virtuals: true,
    transform: function (doc: any, ret: any) {
      delete ret._id;
      delete ret.__v;
      return ret;
    },
  },
  timestamps: true,
})
export class Users extends Document {
  @Prop({
    type: 'string',
    required: false,
    default: '',
  })
  googleId: string;

  @Prop({
    type: 'string',
    required: true,
  })
  username: string;

  @Prop({
    type: 'string',
    required: true,
  })
  email: string;

  @Prop({
    type: 'string',
    required: false,
    default: '',
  })
  password: string;

  @Prop({
    type: 'boolean',
    required: false,
    default: true,
  })
  active: boolean;

  @Prop({
    type: String,
    required: true,
  })
  avatar: string;

  @Prop({
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  })
  role: string;

  // @Prop({
  //   type: MongooseSchema.Types.ObjectId,
  //   ref: 'Subscription',
  //   required: false,
  //   default: null,
  //   autopopulate: {
  //     maxDepth: 1,
  //   },
  // })
  // subscription: string;

  @Prop({
    type: Boolean,
    required: false,
    default: false,
  })
  vipStatus: boolean;

  @Prop({
    type: String,
    required: false,
    default: '',
  })
  phone_number: string;

  @Prop()
  sms_otp: string;

  @Prop()
  sms_otp_created_at: Date;

  @Prop()
  sms_otp_expires_at: Date;

  @Prop()
  number_verified_at: Date;
}

export type UsersDocument = HydratedDocument<Users>;
export const UsersSchema = SchemaFactory.createForClass(Users);
UsersSchema.plugin(require('mongoose-autopopulate'));
