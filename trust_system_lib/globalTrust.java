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

public class globalTrust {
 
    double wp;
    double wn;
    int u;
    boolean state;
   
  
    public globalTrust (){
        wp=0.0;
        wn=0.0;
        u=0;
        state=true;
    }
       public globalTrust (boolean s){
        wp=0.0;
        wn=0.0;
        u=0;
        state=s;
    }
    public void addele (double p,double n,int nu){
        wp=p;
        wn=n;
        u=nu;
        state=true;
    }
    public boolean getstate(){
        return state;
    }
    public void delete(){
        state=false;
         wp=0.0;
        wn=0.0;
        u=0;
    }
    public void updatglobal(int p,int n){
      wp=wp+p;
      wn=wn+n;
    }
     public void addwp(){
		
      wp=wp+1.0;

      
    }
      public void addwn(){
 
      wn=wn+1.0;
 

    }
    public double getwp(){
        return wp;
    }
     public double getwn(){
        return wn;
    }
      public int getnumu(){
        return u;
    }
    public void increaseu(){
        this.u=u+1;
    }
  
}


