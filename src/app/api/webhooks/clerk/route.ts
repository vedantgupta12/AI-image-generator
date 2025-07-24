import { clerkClient } from "@clerk/clerk-sdk-node";
import { WebhookEvent } from "@clerk/nextjs/server";
import { headers } from "next/headers";
import { NextResponse } from "next/server";
import { Webhook } from "svix";

import { createUser, deleteUser, updateUser } from "../../../../lib/actions/user.actions";


export async function POST(req: Request) {
  const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;

  if (!WEBHOOK_SECRET) {
    throw new Error("Please add WEBHOOK_SECRET to .env");
  }

  const headerPayload = headers();
  const svix_id = headerPayload.get("svix-id");
  const svix_timestamp = headerPayload.get("svix-timestamp");
  const svix_signature = headerPayload.get("svix-signature");

  if (!svix_id || !svix_timestamp || !svix_signature) {
    return new Response("Missing Svix headers", { status: 400 });
  }

  const payload = await req.json();
  const body = JSON.stringify(payload);

  const wh = new Webhook(WEBHOOK_SECRET);

  let evt: WebhookEvent;

  try {
    evt = wh.verify(body, {
      "svix-id": svix_id,
      "svix-timestamp": svix_timestamp,
      "svix-signature": svix_signature,
    }) as WebhookEvent;
  } catch (err) {
    console.error("Webhook verification failed:", err);
    return new Response("Invalid signature", { status: 400 });
  }

  const eventType = evt.type;

  if (eventType === "user.created") {
    const { id, email_addresses, image_url, first_name, last_name, username } = evt.data;

    if (!id) {
      return new Response("Missing Clerk user ID", { status: 400 });
    }

    const user = {
      clerkId: id,
      email: email_addresses?.[0]?.email_address ?? "",
      username: username ?? "user",
      firstName: first_name ?? "",
      lastName: last_name ?? "",
      photo: image_url ?? "",
    };

    const newUser = await createUser(user);

    if (newUser) {
      await clerkClient.users.updateUserMetadata(id, {
        publicMetadata: {
          userId: newUser._id,
        },
      });
    }

    return NextResponse.json({ message: "OK", user: newUser });
  }

  if (eventType === "user.updated") {
    const { id, image_url, first_name, last_name, username } = evt.data;

    if (!id) {
      return new Response("Missing Clerk user ID", { status: 400 });
    }

    const user = {
      firstName: first_name ?? "",
      lastName: last_name ?? "",
      username: username ?? "user",
      photo: image_url ?? "",
    };

    const updatedUser = await updateUser(id, user);

    return NextResponse.json({ message: "OK", user: updatedUser });
  }

  if (eventType === "user.deleted") {
    const { id } = evt.data;

    if (!id) {
      return new Response("Missing Clerk user ID", { status: 400 });
    }

    const deletedUser = await deleteUser(id);

    return NextResponse.json({ message: "OK", user: deletedUser });
  }

  console.log(`Unhandled event type: ${eventType}`);
  return new Response("Event not handled", { status: 200 });
}
export{};