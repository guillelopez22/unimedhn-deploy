import { Injectable } from '@angular/core';
import { HttpClient, HttpParams, HttpUrlEncodingCodec, HttpParameterCodec, HttpHeaders } from '@angular/common/http';
import { Observable } from 'rxjs/Observable';
import { Router } from '@angular/router';
import 'rxjs/add/observable/of';
import 'rxjs/add/operator/do';
import 'rxjs/add/operator/delay';
import 'rxjs/add/operator/catch';
import 'rxjs/add/operator/map';
import 'rxjs/add/operator/toPromise';
import 'rxjs/add/observable/throw';

export class FormQueryEncoder implements HttpParameterCodec {
  encodeKey(k: string): string { return encodeURIComponent(k); }
  encodeValue(v: string): string { return encodeURIComponent(v); }
  decodeKey(k: string): string { return encodeURIComponent(k); }
  decodeValue(v: string): string { return encodeURIComponent(v); }
}

@Injectable()
export class AppEndpoints {
  private endpoint: string;

  constructor(private httpClient: HttpClient, private router: Router) {
    // this.endpoint = 'http://' + window.location.hostname + ':8000/api';
    this.endpoint = "http://3.223.73.145:8300/api";
  }

  //########################################################################
  //CATALOGS ###############################################################


  //CATALOGS ###############################################################
  //########################################################################

  //########################################################################
  //AUTH ###################################################################

  login(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('username', payload.username)
      .set('password', payload.password);
    return this.httpClient.get(this.endpoint + '/login', { params: params, responseType: 'json' });
  }

  request_recovery_code(payload): Observable<any> {
    return this.httpClient.post(this.endpoint + '/request_recovery_code', payload, { responseType: 'json' });
  }

  validate_recovery_code(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('id', payload.id)
      .set('user_email', payload.user_email)
      .set('restore_code', payload.restore_code);
    return this.httpClient.get(this.endpoint + '/validate_recovery_code', { params: params, responseType: 'json' });
  }

  request_password_change(payload): Observable<any> {
    return this.httpClient.post(this.endpoint + '/request_password_change', payload, { responseType: 'json' });
  }

  request_password_change_first_login(payload): Observable<any> {
    return this.httpClient.post(this.endpoint + '/request_password_change_first_login', payload, { responseType: 'json' });
  }

  logout() {
    this.reset_session();
  }

  get_session() {
    if (localStorage.getItem('unimed_session')) {
      const object = JSON.parse(localStorage.getItem('unimed_session'));
      if (object) {
        return {
          name: object.name,
          token: object.token,
          role: object.role,
          valid: true,
          user_id: object.id
        };
        return object;
      } else {
        return {
          name: '',
          token: '',
          role: 0,
          valid: false,
          user_id: 0
        };
      }
    } else {
      return {
        name: '',
        token: '',
        role: 0,
        valid: false,
        user_id: 0
      };
    }
  }

  set_session(session) {
    console.log(session);
    localStorage.setItem('unimed_session', JSON.stringify(session));
  }

  reset_session() {
    this.router.navigateByUrl('/conectarse');
    localStorage.removeItem('unimed_session');
  }

  get_headers() {
    if (this.get_session() && this.get_session().token) {
      const headers = new HttpHeaders({
        'Authorization': this.get_session().token
      });
      return headers;
    } else {
      return null;
    }

  }

  //AUTH ###################################################################
  //########################################################################

  //########################################################################
  //INSTITUCIONES ##########################################################

  get_instituciones(payload): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_instituciones', { params: payload, headers: this.get_headers(), responseType: 'json' });
  }

  get_institutions(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_institutions', { headers: this.get_headers(), responseType: 'json' });
  }

  get_all_cartera_products(data): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_all_cartera_products?institution_id=' + data, { headers: this.get_headers(), responseType: 'json' });
  }

  get_institution(data): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_institution?institution_id=' + data, { headers: this.get_headers(), responseType: 'json' });
  }

  insert_institucion(payload): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_institucion', payload, { headers: this.get_headers(), responseType: 'json' });
  }

  update_institucion(payload): Observable<any> {
    return this.httpClient.put(this.endpoint + '/update_institucion', payload, { headers: this.get_headers(), responseType: 'json' });
  }

  delete_institucion(payload): Observable<any> {
    return this.httpClient.delete(this.endpoint + '/delete_institucion', { params: payload, headers: this.get_headers(), responseType: 'json' });
  }

  //INSTITUCIONES ##########################################################
  //########################################################################

  //########################################################################
  //DOCTORS ################################################################
  get_doctors(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/doctors_list', { headers: this.get_headers(), responseType: 'json' });
  }

  doctor_by_institution(data): Observable<any> {
    return this.httpClient.get(this.endpoint + '/doctors_institution_list?institution_id=' + data.institution_id, { headers: this.get_headers(), responseType: 'json' });
  }

  insert_doctors(payload): Observable<any> {
    console.log(payload)
    return this.httpClient.post(this.endpoint + '/insert_doctor', payload, { headers: this.get_headers(), responseType: 'json' });
  }

  get_doctor_by_user(user_id): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_doctor_by_user?user_id=' + user_id, { headers: this.get_headers(), responseType: 'json' });
  }

  update_doctor(payload): Observable<any> {
    return this.httpClient.put(this.endpoint + '/update_doctor', { params: payload, headers: this.get_headers(), responseType: 'json' });
  }

  delete_doctor(data): Observable<any> {
    return this.httpClient.delete(this.endpoint + '/delete_doctor?doctor_id=' + data.doctor_id, { headers: this.get_headers(), responseType: 'json' });
  }



  //DOCTORS ################################################################
  //########################################################################

  //########################################################################
  //DOCTORS ################################################################

  get_alumnos(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/patient_list', { headers: this.get_headers(), responseType: 'json' });
  }

  alumno_by_institution(data): Observable<any> {
    return this.httpClient.get(this.endpoint + '/patients_institution_list?institution_id=' +
            data.institution_id, { headers: this.get_headers(), responseType: 'json' });
  }

  insert_alumno(payload): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_patient', payload, { headers: this.get_headers(), responseType: 'json' });
  }

  update_alumno(payload): Observable<any> {
    return this.httpClient.get(this.endpoint + '/update_patient', { params: payload, headers: this.get_headers(), responseType: 'json' });
  }

  delete_alumno(payload): Observable<any> {
    return this.httpClient.get(this.endpoint + '/delete_patient', { params: payload, headers: this.get_headers(), responseType: 'json' });
  }

  //DOCTORS ################################################################
  //########################################################################

  //########################################################################
  //ACTIVE PRINCIPLES ######################################################

  get_all_insumos(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_all_insumos', { responseType: 'json' });
  }

  get_all_medicamentos(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_all_medicamentos', { responseType: 'json' });
  }

  insert_active_principle(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_active_principle', data, { headers: this.get_headers(), responseType: 'json' });
  }

  update_active_principle(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('active_principle_id', payload.active_principle_id)
      .set('name', payload.name)
      .set('description', payload.description);
    return this.httpClient.put(this.endpoint + '/update_active_principle', params, { responseType: 'json' });
  }

  delete_active_principle(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('active_principle_id', payload);
    return this.httpClient.delete(this.endpoint + '/delete_active_principle', { params: params, responseType: 'json' });
  }

  //ACTIVE PRINCIPLES ######################################################
  //########################################################################


  //########################################################################
  //TRADENAMES #############################################################

  get_tradename_list(active_principle_id): Observable<any> {
    return this.httpClient.get(this.endpoint +
      '/get_tradename_list?active_principle_id=' + active_principle_id , { headers: this.get_headers(), responseType: 'json' });
  }

  insert_tradename(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_tradename', data, { headers: this.get_headers(), responseType: 'json' });
  }
  update_tradename(data): Observable<any> {
    return this.httpClient.put(this.endpoint + '/update_tradename',  data, { headers: this.get_headers(), responseType: 'json' });
  }

  delete_tradename(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('tradename_id', payload);
    return this.httpClient.delete(this.endpoint + '/delete_tradename', { params: params, responseType: 'json' });
  }

  //TRADENAMES #############################################################
  //########################################################################

  //########################################################################
  //CONCENTRATIONS #########################################################


  get_concentrations_list(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_concentrations_list', { responseType: 'json' });
  }

  insert_concentrations(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_concentration', data, { headers: this.get_headers(), responseType: 'json' });
  }

  insert_consulta(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_consulta', data, { headers: this.get_headers(), responseType: 'json' });
  }

  update_concentrations(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('concentration_id', payload.concentration_id)
      .set('quantity1', payload.quantity1)
      .set('measure_unit_id1', payload.measure_unit_id1)
      .set('quantity2', payload.quantity2)
      .set('measure_unit_id2', payload.measure_unit_id2)
      .set('description', payload.description);
    return this.httpClient.put(this.endpoint + '/update_concentrations', params, { responseType: 'json' });
  }

  delete_concentrations(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('concentration_id', payload);
    return this.httpClient.delete(this.endpoint + '/delete_concentrations', { params: params, responseType: 'json' });
  }

  //CONCENTRATIONS #########################################################
  //########################################################################

  get_presentation_list(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_presentation_list', { responseType: 'json' });
  }

  get_measure_units_list(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_measure_units_list', { responseType: 'json' });
  }

  get_products_list(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_products_list', { responseType: 'json' });
  }

  get_cartera_batch_product(data): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_cartera_batch_product?batch_product_id=' + data.batch_product_id + "&cartera_id="+ data.cartera_id, { responseType: 'json' });
  }

  insert_producto(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('tradename_id', payload.tradename_id)
      .set('presentation_id', payload.presentation_id)
      .set('concentration_id', payload.concentration_id)
      .set('presentation_quantity', payload.presentation_quantity)
      .set('presentation_measure_unit_id', payload.presentation_measure_unit_id)
      .set('aus_quantity', payload.aus_quantity)
      .set('aus_measure_unit_id', payload.aus_measure_unit_id)
      .set('pum', payload.pum)
      .set('pum_measure_unit_id', payload.pum_measure_unit_id);
    return this.httpClient.post(this.endpoint + '/insert_producto', params, { responseType: 'json' });
  }

  update_producto(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('product_id', payload.product_id)
      .set('tradename_id', payload.tradename_id)
      .set('presentation_id', payload.presentation_id)
      .set('concentration_id', payload.concentration_id)
      .set('presentation_quantity', payload.presentation_quantity)
      .set('presentation_measure_unit_id', payload.presentation_measure_unit_id)
      .set('aus_quantity', payload.aus_quantity)
      .set('aus_measure_unit_id', payload.aus_measure_unit_id)
      .set('description', payload.description);
    return this.httpClient.put(this.endpoint + '/update_producto', params, { responseType: 'json' });
  }

  delete_producto(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('product_id', payload);
    return this.httpClient.delete(this.endpoint + '/delete_producto', { params: params, responseType: 'json' });
  }

  get_batchs_list(product_id): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('product_id', product_id);
    return this.httpClient.get(this.endpoint + '/get_batchs_list', { params: params, responseType: 'json' });
  }

  get_all_batchs(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_all_batchs', { headers: this.get_headers(), responseType: 'json' });
  }

  get_batch(id): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_batch?batch_id=' + id, { headers: this.get_headers(), responseType: 'json' });
  }

  get_batch_products(id): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_batch_products?batch_id=' + id, { headers: this.get_headers(), responseType: 'json' });
  }

  insert_batch_product(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_batch_product', data, { headers: this.get_headers(), responseType: 'json' });
  }

  use_cartera_product(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/use_cartera_product', data, { headers: this.get_headers(), responseType: 'json' });
  }

  insert_batch(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_batch', data, { headers: this.get_headers(), responseType: 'json' });
  }

  get_all_cartera_info() {
    return this.httpClient.get(this.endpoint + '/get_all_cartera_info', { responseType: 'json' });
  }

  get_all_cartera_insumo_info() {
    return this.httpClient.get(this.endpoint + '/get_all_cartera_insumo_info', { responseType: 'json' });
  }

  update_batch(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('batch_id', payload.batch_id)
      .set('product_id', payload.product_id)
      .set('expiration_date', payload.expiration_date)
      .set('purchase_date', payload.purchase_date)
      .set('batch_price', payload.batch_price)
      .set('batch_quantity', payload.batch_quantity)
      .set('observation', payload.observation);
    return this.httpClient.put(this.endpoint + '/update_batch', params, { responseType: 'json' });
  }

  delete_batch(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('batch_id', payload);
    return this.httpClient.delete(this.endpoint + '/delete_batch', { params: params, responseType: 'json' });
  }

  get_active_principle_total_list(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_active_principles_list', { responseType: 'json' });
  }

  get_batchs_for_asign_list(product_id): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('product_id', product_id);
    return this.httpClient.get(this.endpoint + '/get_batchs_for_asign_list', { params: params, responseType: 'json' });
  }

  insert_cartera_productos(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('cartera_id', payload.cartera_id)
      .set('product_id', payload.product_id)
      .set('batch_id', payload.batch_id)
      .set('quantity', payload.quantity);
    return this.httpClient.post(this.endpoint + '/insert_cartera_productos', params, { responseType: 'json' });
  }

  get_cartera_productos_list(product_id): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('product_id', product_id);
    return this.httpClient.get(this.endpoint + '/get_cartera_productos_list', { params: params, responseType: 'json' });
  }

  update_cartera_productos(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('cartera_medicamentos_id', payload.cartera_medicamentos_id)
      .set('cartera_id', payload.cartera_id)
      .set('product_id', payload.product_id)
      .set('batch_id', payload.batch_id)
      .set('quantity', payload.quantity);
    return this.httpClient.put(this.endpoint + '/update_cartera_productos', params, { responseType: 'json' });
  }

  delete_cartera_productos(payload): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('cartera_medicamentos_id', payload);
    return this.httpClient.delete(this.endpoint + '/delete_cartera_productos', { params: params, responseType: 'json' });
  }

  get_carteras_by_active_principle_list(active_principle_id): Observable<any> {
    const params = new HttpParams({ encoder: new FormQueryEncoder() })
      .set('active_principle_id', active_principle_id);
    return this.httpClient.get(this.endpoint + '/get_carteras_by_active_principle_list', { params: params, responseType: 'json' });
  }



  // medicamentos
  insert_medicamento(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_medicamento', data, { headers: this.get_headers(), responseType: 'json' });
  }

  update_medicamento(payload): Observable<any> {
    const params = new HttpParams({encoder: new FormQueryEncoder()})
    .set('medicamento_id', payload.medicamento_id)
    .set('nombre', payload.nombre)
    .set('nombre_comercial', payload.nombre_comercial)
    .set('presentacion', payload.presentacion)
    .set('concentracion', payload.concentracion);
    return this.httpClient.put(this.endpoint + '/update_medicamento', params, {responseType: 'json'});
  }

  delete_medicamento(payload): Observable<any> {
    const params = new HttpParams({encoder: new FormQueryEncoder()})
    .set('medicamento_id', payload);
    return this.httpClient.delete(this.endpoint + '/delete_medicamento', {params: params, responseType: 'json'});
  }

  get_medicamentos_list(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_medicamentos_list', {responseType: 'json'});
  }

  get_medicamentos_list_cartera(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_medicamentos_list_cartera', {responseType: 'json'});
  }

  insert_inventario_medicamento(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_inventario_medicamento',
    data, { headers: this.get_headers(), responseType: 'json' });
  }

  update_inventario_medicamento(payload): Observable<any> {
    const params = new HttpParams({encoder: new FormQueryEncoder()})
    .set('inventario_id', payload.inventario_id)
    .set('costo_compra', payload.costo_compra.replace(/,/g, ''))
    .set('cantidad_dosis', payload.cantidad_dosis.replace(/,/g, ''))
    .set('costo_dosis', payload.costo_dosis.replace(/,/g, ''))
    .set('vencimiento', payload.vencimiento)
    .set('comentarios', payload.comentarios)
    .set('numero_inventario', payload.numero_inventario);
    return this.httpClient.put(this.endpoint + '/update_inventario_medicamento', params, {responseType: 'json'});
  }

  delete_inventario_medicamento(payload): Observable<any> {
    const params = new HttpParams({encoder: new FormQueryEncoder()})
    .set('inventario_id', payload);
    return this.httpClient.delete(this.endpoint + '/delete_inventario_medicamento', {params: params, responseType: 'json'});
  }

  get_inventario_medicamentos_list(payload): Observable<any> {
    const params = new HttpParams({encoder: new FormQueryEncoder()})
    .set('medicamento_id', payload);
    return this.httpClient.get(this.endpoint + '/get_inventario_medicamentos_list', {params: params, responseType: 'json'});
  }

  get_inventario_medicamento(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_inventario_medicamento', {responseType: 'json'});
  }

  get_inventario_insumos(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_inventario_insumo', {responseType: 'json'});
  }

  // insumos

  insert_inventario_insumo(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_inventario_insumos',
    data, { headers: this.get_headers(), responseType: 'json' });
  }

  update_inventario_insumo(payload): Observable<any> {
    const params = new HttpParams({encoder: new FormQueryEncoder()})
    .set('inventario_id', payload.inventario_id)
    .set('costo_compra', payload.costo_compra.replace(/,/g, ''))
    .set('cantidad', payload.cantidad.replace(/,/g, ''))
    .set('costos_atencion', payload.costos_atencion.replace(/,/g, ''))
    .set('vencimiento', payload.vencimiento)
    .set('comentarios', payload.comentarios)
    .set('numero_inventario', payload.numero_inventario);
    return this.httpClient.put(this.endpoint + '/update_inventario_insumo', params, {responseType: 'json'});
  }

  delete_inventario_insumo(payload): Observable<any> {
    const params = new HttpParams({encoder: new FormQueryEncoder()})
    .set('inventario_id', payload);
    return this.httpClient.delete(this.endpoint + '/delete_inventario_insumo', {params: params, responseType: 'json'});
  }

  get_inventario_insumos_list(payload): Observable<any> {
    const params = new HttpParams({encoder: new FormQueryEncoder()})
    .set('insumo_id', payload);
    return this.httpClient.get(this.endpoint + '/get_inventario_insumos_list', {params: params, responseType: 'json'});
  }

  insert_insumo(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_insumo', data, { headers: this.get_headers(), responseType: 'json' });
  }

  update_insumo(payload): Observable<any> {
    const params = new HttpParams({encoder: new FormQueryEncoder()})
    .set('insumo_id', payload.insumo_id)
    .set('nombre_comercial', payload.nombre_comercial)
    .set('tipo_insumo', payload.tipo_insumo)
    .set('presentacion', payload.presentacion);
    return this.httpClient.put(this.endpoint + '/update_insumo', params, {responseType: 'json'});
  }

  delete_insumo(payload): Observable<any> {
    const params = new HttpParams({encoder: new FormQueryEncoder()})
    .set('insumo_id', payload);
    return this.httpClient.delete(this.endpoint + '/delete_insumo', {params: params, responseType: 'json'});
  }

  get_insumos_list(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_insumos_list', {responseType: 'json'});
  }

  get_consultas(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_consultas', {responseType: 'json'});
  }

  get_consultas_by_doctor(data): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_consultas_by_doctor?doctor_id=' + data.doctor_id, {responseType: 'json'});
  }

  get_available_inventory(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_available_inventory', {responseType: 'json'});
  }

  get_insumos_list_cartera(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_insumos_list_cartera', {responseType: 'json'});
  }

  get_institution_cartera(institution_id): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_institution_cartera?institution_id=' +
    institution_id, { headers: this.get_headers(), responseType: 'json' });
  }

  insert_cartera(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_cartera', data, { headers: this.get_headers(), responseType: 'json' });
  }

  insert_cartera_batch_products(data): Observable<any> {
    return this.httpClient.post(this.endpoint + '/insert_cartera_batch_products',
    data, { headers: this.get_headers(), responseType: 'json' });
  }

  get_medicamento_inventory(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_medicamento_inventory', {responseType: 'json'});
  }

  get_insumo_inventory(): Observable<any> {
    return this.httpClient.get(this.endpoint + '/get_insumo_inventory', {responseType: 'json'});
  }

}



