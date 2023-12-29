import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { HydratedDocument, Document } from 'mongoose';

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
export class ContactUs extends Document {
  @Prop({
    type: 'string',
    required: true,
  })
  name: string;

  @Prop({
    type: 'string',
    required: true,
  })
  email: string;

  @Prop({
    type: 'string',
    required: true,
  })
  message: string;

  @Prop({
    type: 'string',
    required: false,
    enum: ['pending', 'completed'],
    default: 'pending',
  })
  status: string;
}

export type ContactUsDocument = HydratedDocument<ContactUs>;
export const ContactUsSchema = SchemaFactory.createForClass(ContactUs);
