/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package trust_system_lib;

/**
 *
 * @author Fatimah almuzaini
 */
public class Trustinfo {

    private int pos;
    private int neg;
    
    public Trustinfo(){
    
        pos=0;
        neg=0;
    }
    public void updatetrustinfo(int p,int n){
        pos=pos+p;
        neg=neg+n;
    }
    public void addpos(){
       pos=pos + 1;
   }
    public void addneg(){
       neg=neg + 1;
   }
     public int getpos(){
       return pos;
   }
      public int getneg(){
       return neg;
   }
      	
}
