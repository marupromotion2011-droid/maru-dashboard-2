document.querySelectorAll(".q[data-a]").forEach(function(box){
  var a=+box.getAttribute("data-a");
  box.querySelectorAll("button").forEach(function(b){
    b.addEventListener("click",function(){
      if(box.classList.contains("done"))return;
      box.classList.add("done");
      var j=+b.getAttribute("data-j");
      b.classList.add(j===a?"ok":"no");
      if(j!==a){
        var c=box.querySelectorAll("button")[a];
        if(c)c.classList.add("ok");
      }
      var w=box.querySelector(".why");
      if(w)w.classList.add("show");
    });
  });
});
