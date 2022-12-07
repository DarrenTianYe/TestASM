/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.example.hellojnicallback;

import androidx.annotation.Keep;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;

import android.Manifest;
import android.Manifest.permission;
import android.annotation.SuppressLint;
import android.content.Context;
import android.content.pm.PackageManager;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.provider.Settings;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.NetworkInterface;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;

import static android.Manifest.permission.ACCESS_COARSE_LOCATION;

public class MainActivity extends AppCompatActivity {

    int hour = 0;
    int minute = 0;
    int second = 0;
    TextView tickView;
    Button but ;
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        tickView = (TextView) findViewById(R.id.tickView);
        but = (Button) findViewById(R.id.button2);

        but.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                stringFromJNI12();
            }
        });

    }
    @Override
    public void onResume() {
        super.onResume();
        hour = minute = second = 0;
        ((TextView)findViewById(R.id.hellojniMsg)).setText(stringFromJNI12());
//        startTicks();
//
//        int pid = android.os.Process.myPid();
//        getAllFiles("/proc/"+pid+"/fd", "xx");
//        MainActivity.this.tickView.setText(getMACAddress(getApplicationContext()));
    }

    @Override
    public void onPause () {
        super.onPause();
        //StopTicks();
    }

    /*
     * A function calling from JNI to update current timer
     */
    @Keep
    private void updateTimer() {
        ++second;
        if(second >= 60) {
            ++minute;
            second -= 60;
            if(minute >= 60) {
                ++hour;
                minute -= 60;
            }
        }
        runOnUiThread(new Runnable() {
            @Override
            public void run() {

                Log.e("tian", "runOnUiThread:");
//                String ticks = "" + MainActivity.this.hour + ":" +
//                        MainActivity.this.minute + ":" +
//                        MainActivity.this.second;
//                MainActivity.this.tickView.setText(getMACAddress(getApplicationContext()));
            }
        });
    }

    public static JSONArray getAllFiles(String dirPath, String _type) {
        File f = new File(dirPath);
        if (!f.exists()) {//判断路径是否存在
            return null;
        }

        File[] files = f.listFiles();

        if(files==null){//判断权限
            return null;
        }

        JSONArray fileList = new JSONArray();
        for (File _file : files) {//遍历目录
            Log.e("darren", _file.getAbsolutePath());
            if(_file.isFile() && _file.getName().endsWith(_type)){
                String _name=_file.getName();
                String filePath = _file.getAbsolutePath();//获取文件路径
                String fileName = _file.getName().substring(0,_name.length()-4);//获取文件名
//                Log.d("LOGCAT","fileName:"+fileName);
//                Log.d("LOGCAT","filePath:"+filePath);
                try {
                    JSONObject _fInfo = new JSONObject();
                    _fInfo.put("name", fileName);
                    _fInfo.put("path", filePath);
                    fileList.put(_fInfo);
                }catch (Exception e){
                }
            } else if(_file.isDirectory()){//查询子目录
                getAllFiles(_file.getAbsolutePath(), _type);
            } else{
            }
        }
        return fileList;
    }

    /**
     * 获取MAC地址
     *
     * @param context Android 上下文
     * @return MAC Address
     */
    public static String getMACAddress1(Context context) {
        String mac11 = "";
        try {
            @SuppressLint("WifiManagerPotentialLeak")
            WifiManager wifiManager = (WifiManager)context.getSystemService(Context.WIFI_SERVICE);
            if (wifiManager != null) {
                WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                mac11 = wifiInfo.getMacAddress();
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return mac11;
    }

    /**
     * 获取MAC地址
     *
     * @param context Android 上下文
     * @return MAC Address
     */
    public static String getMACAddress(Context context) {
        String mac11 = "";
        String mac12 = "";
        String androidId = null;
        try {
            @SuppressLint("WifiManagerPotentialLeak")
            WifiManager wifiManager = (WifiManager)context.getSystemService(Context.WIFI_SERVICE);
            if (wifiManager != null) {
                @SuppressLint("MissingPermission")
                WifiInfo wifiInfo = wifiManager.getConnectionInfo();
                mac11 = wifiInfo.getMacAddress();

                Log.e("tian", "mac11:"+mac11);
                mac12 = getMacByFile("wlan0");
               // Log.e("tian", "getMacAddress"+getMacAddress());
            }
            androidId = Settings.Secure.getString(context.getContentResolver(), Settings.Secure.ANDROID_ID);
            Log.e("tian", "wlan0:"+android_command("ip address show wlan0"));
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return "\nmac1:"+mac11+"\nmac2:"+mac12+"\n||mac3:"+getMacAddress()+"\n|| nandroid_id:"+androidId
                +"\n commod:"+android_command("ip address show wlan0");
    }

    public static String android_command (String command) {
        Process process = null;
        BufferedReader reader = null;
        StringBuffer buffer = new StringBuffer();
        String temp;
        try {
            process = Runtime.getRuntime().exec(command);
            reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            while ((temp = reader.readLine()) != null) {
                buffer.append(temp);
            }
            return buffer.toString();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return "";
    }

    /**
     *  通过文件读取 mac 地址
     *
     * @param name 接口名
     * @return mac
     */
    private static String getMacByFile(String name) {
        String mac = "";
        try {
            Log.e("tian", "getMacByFile:"+name);


            File file = new File("/sys/class/net/" + name, "address");
            if (file.exists() && file.isFile() && file.canRead()) {
                FileInputStream fis = new FileInputStream(file);
                int len = fis.available();
                byte[] bytes = new byte[len];
                fis.read(bytes, 0, len);
                mac = new String(bytes);

                mac = mac.substring(0, 17).toUpperCase();
            }
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return mac;
    }

    private static String getMacAddress() {
        try {
            List<NetworkInterface> all = Collections.list(NetworkInterface.getNetworkInterfaces());
            for (NetworkInterface nif : all) {
                if (!nif.getName().equalsIgnoreCase("wlan0")) {
                    continue;
                }
                byte[] macBytes = nif.getHardwareAddress();
                if (macBytes == null) {
                    return "";
                }
                StringBuilder res1 = new StringBuilder();
                for (byte b : macBytes) {
                    res1.append(String.format("%02X:", b));
                }
                if (res1.length() > 0) {
                    res1.deleteCharAt(res1.length() - 1);
                }
                return res1.toString();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    static {
        System.loadLibrary("hello-jnicallback");
    }
    public native  String stringFromJNI12();
    public static  native  String staticstringFromJNI();
    public native void startTicks();
    public native void StopTicks();
    //public static String getNativeVersion(String tmp);
}
