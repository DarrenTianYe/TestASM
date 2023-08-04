//package com.example.usb;
//
//import android.app.PendingIntent;
//import android.content.Context;
//import android.content.Intent;
//import android.util.Log;
//
//import java.io.IOException;
//
//import me.jahnen.libaums.core.UsbMassStorageDevice;
//import me.jahnen.libaums.core.fs.FileSystem;
//
//public class Test {
//
//    public static final String TAG = "USB_Darren";
//
//
//    public void test1(Context context) throws IOException {
//
//
////        PendingIntent permissionIntent = PendingIntent.getBroadcast(this, 0, new Intent(ACTION_USB_PERMISSION), 0);
////        usbManager.requestPermission(device.getUsbDevice(), permissionIntent);
//
//
//        UsbMassStorageDevice[] devices = UsbMassStorageDevice.getMassStorageDevices(context /* Context or Activity */);
//
//        for(UsbMassStorageDevice device: devices) {
//
//            // before interacting with a device you need to call init()!
//            device.init();
//
//            // Only uses the first partition on the device
//            FileSystem currentFs = device.getPartitions().get(0).getFileSystem();
//            Log.d(TAG, "Capacity: " + currentFs.getCapacity());
//            Log.d(TAG, "Occupied Space: " + currentFs.getOccupiedSpace());
//            Log.d(TAG, "Free Space: " + currentFs.getFreeSpace());
//            Log.d(TAG, "Chunk size: " + currentFs.getChunkSize());
//        }
//
//    }
//
//}
